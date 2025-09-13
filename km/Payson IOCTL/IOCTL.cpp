#include <ntifs.h>
#include <windef.h>
#include <intrin.h>

// �X�ʦW�ٻP�Ÿ��챵
UNICODE_STRING DriverName, SymbolicLinkName;

// ���c�w�q
typedef struct _SystemBigpoolEntry {
    PVOID VirtualAddress;
    ULONG_PTR NonPaged : 1;
    ULONG_PTR SizeInBytes;
    UCHAR Tag[4];
} SystemBigpoolEntry, * PSystemBigpoolEntry;

typedef struct _SystemBigpoolInformation {
    ULONG Count;
    SystemBigpoolEntry AllocatedInfo[1];
} SystemBigpoolInformation, * PSystemBigpoolInformation;

typedef enum _SystemInformationClass {
    SystemBigpoolInformationClass = 0x42,
} SystemInformationClass;

// �~���禡�ŧi
extern "C" NTSTATUS NTAPI IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
extern "C" PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(SystemInformationClass systemInformationClass, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);

// ����X�P�`��
#define PaysonRead CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1363, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define PaysonBase CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1369, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define PaysonSecurity 0x85F8AC8

// Windows build ���� offsets
#define Win1803 17134
#define Win1809 17763
#define Win1903 18362
#define Win1909 18363
#define Win2004 19041
#define Win20H2 19569
#define Win21H1 20180

#define PageOffsetSize 12
static const UINT64 PageMask = (~0xfull << 8) & 0xfffffffffull;

// �ШD���c
typedef struct _ReadWriteRequest {
    INT32 Security;
    INT32 ProcessId;
    ULONGLONG Address;
    ULONGLONG Buffer;
    ULONGLONG Size;
    BOOLEAN Write;
} ReadWriteRequest, * PReadWriteRequest;

typedef struct _BaseAddressRequest {
    INT32 Security;
    INT32 ProcessId;
    ULONGLONG* Address;
} BaseAddressRequest, * PBaseAddressRequest;

// ���z�O����Ū��
NTSTATUS ReadPhysicalMemory(PVOID TargetAddress, PVOID Buffer, SIZE_T Size, SIZE_T* BytesRead) {
    MM_COPY_ADDRESS CopyAddress = {};
    CopyAddress.PhysicalAddress.QuadPart = (LONGLONG)TargetAddress;
    return MmCopyMemory(Buffer, CopyAddress, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
}

// �P�_ Windows �������� offset
INT32 GetWindowsVersion() {
    RTL_OSVERSIONINFOW VersionInfo = { 0 };
    RtlGetVersion(&VersionInfo);

    switch (VersionInfo.dwBuildNumber) {
    case Win1803:
    case Win1809:
        return 0x0278;
    case Win1903:
    case Win1909:
        return 0x0280;
    case Win2004:
    case Win20H2:
    case Win21H1:
    default:
        return 0x0388;
    }
}

// ��� CR3�]DirectoryTableBase�^
UINT64 GetProcessCr3(PEPROCESS Process) {
    if (!Process) return 0;

    uintptr_t dirbase = *(uintptr_t*)((UINT8*)Process + 0x28);

    if (!dirbase) {
        ULONG offset = GetWindowsVersion();
        dirbase = *(uintptr_t*)((UINT8*)Process + offset);
    }

    if ((dirbase >> 0x38) == 0x40) {
        uintptr_t savedDirBase = 0;
        KAPC_STATE apc_state{};
        KeStackAttachProcess(Process, &apc_state);
        savedDirBase = __readcr3();
        KeUnstackDetachProcess(&apc_state);
        return savedDirBase;
    }

    return dirbase;
}

// �����a�} -> ���z�a�}�ഫ
UINT64 TranslateLinearAddress(UINT64 DirectoryTableBase, UINT64 VirtualAddress) {
    DirectoryTableBase &= ~0xf;

    UINT64 PageOffset = VirtualAddress & 0xFFF;
    UINT64 PteIndex = (VirtualAddress >> 12) & 0x1FF;
    UINT64 PtIndex = (VirtualAddress >> 21) & 0x1FF;
    UINT64 PdIndex = (VirtualAddress >> 30) & 0x1FF;
    UINT64 PdpIndex = (VirtualAddress >> 39) & 0x1FF;

    SIZE_T ReadSize = 0;
    UINT64 PdpEntry = 0;

    if (ReadPhysicalMemory((PVOID)(DirectoryTableBase + 8 * PdpIndex), &PdpEntry, sizeof(PdpEntry), &ReadSize) || ~PdpEntry & 1)
        return 0;

    UINT64 PdEntry = 0;
    if (ReadPhysicalMemory((PVOID)((PdpEntry & PageMask) + 8 * PdIndex), &PdEntry, sizeof(PdEntry), &ReadSize) || ~PdEntry & 1)
        return 0;

    if (PdEntry & 0x80)
        return (PdEntry & (~0ull << 42 >> 12)) + (VirtualAddress & ~(~0ull << 30));

    UINT64 PtEntry = 0;
    if (ReadPhysicalMemory((PVOID)((PdEntry & PageMask) + 8 * PtIndex), &PtEntry, sizeof(PtEntry), &ReadSize) || ~PtEntry & 1)
        return 0;

    if (PtEntry & 0x80)
        return (PtEntry & PageMask) + (VirtualAddress & ~(~0ull << 21));

    UINT64 PteEntry = 0;
    if (ReadPhysicalMemory((PVOID)((PtEntry & PageMask) + 8 * PteIndex), &PteEntry, sizeof(PteEntry), &ReadSize) || !PteEntry)
        return 0;

    return (PteEntry & PageMask) + PageOffset;
}

// �̤p�ȿ�ܾ�
ULONG64 FindMin(INT32 A, SIZE_T B) {
    return (A < (INT32)B) ? A : (INT32)B;
}

// Handle Read �ШD
NTSTATUS HandleReadRequest(PReadWriteRequest Request) {
    if (Request->Security != PaysonSecurity || !Request->ProcessId)
        return STATUS_UNSUCCESSFUL;

    PEPROCESS Process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)Request->ProcessId, &Process)))
        return STATUS_UNSUCCESSFUL;

    ULONGLONG DirBase = GetProcessCr3(Process);
    ObDereferenceObject(Process);

    SIZE_T Offset = 0;
    SIZE_T TotalSize = Request->Size;

    INT64 PhysicalAddress = TranslateLinearAddress(DirBase, Request->Address + Offset);
    if (!PhysicalAddress)
        return STATUS_UNSUCCESSFUL;

    ULONG64 FinalSize = FindMin(PAGE_SIZE - (PhysicalAddress & 0xFFF), TotalSize);
    SIZE_T BytesRead = 0;

    ReadPhysicalMemory((PVOID)PhysicalAddress, (PVOID)(Request->Buffer + Offset), FinalSize, &BytesRead);

    return STATUS_SUCCESS;
}

// Handle BaseAddress �ШD
NTSTATUS HandleBaseAddressRequest(PBaseAddressRequest Request) {
    if (Request->Security != PaysonSecurity || !Request->ProcessId)
        return STATUS_UNSUCCESSFUL;

    PEPROCESS Process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)Request->ProcessId, &Process)))
        return STATUS_UNSUCCESSFUL;

    ULONGLONG ImageBase = (ULONGLONG)PsGetProcessSectionBaseAddress(Process);
    ObDereferenceObject(Process);

    if (!ImageBase) return STATUS_UNSUCCESSFUL;

    RtlCopyMemory(Request->Address, &ImageBase, sizeof(ImageBase));
    return STATUS_SUCCESS;
}

// IO ����B�z
NTSTATUS IoControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS Status = {};
    ULONG BytesReturned = 0;
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG IoControlCode = Stack->Parameters.DeviceIoControl.IoControlCode;

    if (IoControlCode == PaysonRead && Stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(ReadWriteRequest)) {
        Status = HandleReadRequest((PReadWriteRequest)Irp->AssociatedIrp.SystemBuffer);
        BytesReturned = sizeof(ReadWriteRequest);
    }
    else if (IoControlCode == PaysonBase && Stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(BaseAddressRequest)) {
        Status = HandleBaseAddressRequest((PBaseAddressRequest)Irp->AssociatedIrp.SystemBuffer);
        BytesReturned = sizeof(BaseAddressRequest);
    }
    else {
        Status = STATUS_INFO_LENGTH_MISMATCH;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = BytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

// ���䴩�� IRP Dispatch
NTSTATUS UnsupportedDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}

// �䴩�}�� IRP
NTSTATUS DispatchHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}

// ���� Driver
void UnloadDriver(PDRIVER_OBJECT DriverObject) {
    IoDeleteSymbolicLink(&SymbolicLinkName);
    IoDeleteDevice(DriverObject->DeviceObject);
}

// ��l���X��
NTSTATUS InitializeDriver(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS Status = STATUS_SUCCESS;
    PDEVICE_OBJECT DeviceObject = NULL;

    RtlInitUnicodeString(&DriverName, L"\\Device\\{sdfjkn4e78hhsjk-sdfjnas78adasd}");
    RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\{sdfjkn4e78hhsjk-sdfjnas78adasd}");

    Status = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
    if (!NT_SUCCESS(Status)) return Status;

    Status = IoCreateSymbolicLink(&SymbolicLinkName, &DriverName);
    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(DeviceObject);
        return Status;
    }

    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = UnsupportedDispatch;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControlHandler;
    DriverObject->DriverUnload = UnloadDriver;

    DeviceObject->Flags |= DO_BUFFERED_IO;
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return Status;
}

// DriverEntry�]�J�f�^
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("DbgLog: RegistryPath found.");
    DbgPrint("Made by guns.lol/Payson1337");

    return IoCreateDriver(NULL, InitializeDriver);
}
