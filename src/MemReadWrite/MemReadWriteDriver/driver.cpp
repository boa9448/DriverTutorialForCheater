#include <ntifs.h>
#include <ntddk.h>

#include "../MemReadWriteCode.h"


#define Log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MemReadWriteDriver]" format "\n", ##__VA_ARGS__)




//https://www.geoffchappell.com/studies/windows/km/ntoskrnl/history/names60.htm
//커널에서 내보내짐 ㅅ;ㅂ;
typedef NTSTATUS (NTAPI* MMCOPYVIRTUALMEMORY)(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize
);

MMCOPYVIRTUALMEMORY MmCopyVirtualMemory = NULL;


UNICODE_STRING Win32Device;
UNICODE_STRING DeviceName;


void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    IoDeleteSymbolicLink(&Win32Device);
    IoDeleteDevice(DriverObject->DeviceObject);
    Log("[+] DriverUnload call");
}


NTSTATUS DriverDefaultHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_NOT_SUPPORTED;
}


NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


NTSTATUS ReadVirtualMemory(ULONG ProcessID, PVOID SourceAddress, PVOID TargetAddress, ULONG Size)
{
    PEPROCESS Process = NULL;
    NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)ProcessID, &Process);
    if (!NT_SUCCESS(Status))
    {
        Log("[-] PsLookupProcessByProcessId fail ... %u", Status);
        return Status;
    }

    SIZE_T ReturnSize = 0;
    Status = MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(), TargetAddress, Size, KernelMode, &ReturnSize);
    return Status;
}


NTSTATUS WriteVirtualMemory(ULONG ProcessID, PVOID SourceAddress, PVOID TargetAddress, ULONG Size)
{
    PEPROCESS Process = NULL;
    NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)ProcessID, &Process);
    if (!NT_SUCCESS(Status))
    {
        Log("[-] PsLookupProcessByProcessId fail ... %u", Status);
        return Status;
    }

    SIZE_T ReturnSize = 0;
    Status = MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process, TargetAddress, Size, KernelMode, &ReturnSize);
    return Status;
}


NTSTATUS ControlProc(ULONG ControlCode, PVOID Buffer, ULONG_PTR* Information)
{
    NTSTATUS Status = STATUS_SUCCESS;

    if (ControlCode == IO_CTL_READ_REQUEST)
    {
        PREAD_REQUEST Info = (PREAD_REQUEST)Buffer;
        Status = ReadVirtualMemory(Info->ProcessID, (PVOID)Info->Address, &Info->Response, Info->Size);

        Log("[ ] Read Param : %lu, 0x%llx", Info->ProcessID, Info->Address);
        Log("[ ] Read Value : %llu", Info->Response);

        *Information = Status == STATUS_SUCCESS ? sizeof(READ_REQUEST) : 0;
    }
    else if (ControlCode == IO_CTL_WRITE_REQUEST)
    {
        PWRITE_REQUEST Info = (PWRITE_REQUEST)Buffer;
        Status = ReadVirtualMemory(Info->ProcessID, &Info->Value, (PVOID)Info->Address, Info->Size);

        Log("[ ] Write Param : %lu, 0x%llx, %llu", Info->ProcessID, Info->Address, Info->Value);

        *Information = Status == STATUS_SUCCESS ? sizeof(WRITE_REQUEST) : 0;
    }
    else
    {
        *Information = 0;
        Status = STATUS_NOT_SUPPORTED;
    }

    return Status;
}

NTSTATUS DriverControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG_PTR Information = 0;

    PIO_STACK_LOCATION IoStackIrp = IoGetCurrentIrpStackLocation(Irp);
    if (IoStackIrp)
    {
        ULONG ControlCode = IoStackIrp->Parameters.DeviceIoControl.IoControlCode;
        PVOID Buffer = Irp->AssociatedIrp.SystemBuffer;
        Status = ControlProc(ControlCode, Buffer, &Information);
    }
    else
    {
        Status = STATUS_UNSUCCESSFUL;
        Information = 0;
    }

    Irp->IoStatus.Information = Information;
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}


extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    Log("[+] DriverEntry call");

    for (int Idx = 0; Idx < IRP_MJ_MAXIMUM_FUNCTION; Idx++)
        DriverObject->MajorFunction[Idx] = DriverDefaultHandler;

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverControl;


    RtlInitUnicodeString(&DeviceName, L"\\Device\\MemReadWriteDriver");
    RtlInitUnicodeString(&Win32Device, L"\\DosDevices\\MemReadWriteDriver");

    PDEVICE_OBJECT DeviceObject = NULL;
    NTSTATUS Status = IoCreateDevice(DriverObject
                                    , 0
                                    , &DeviceName
                                    , FILE_DEVICE_UNKNOWN
                                    , FILE_DEVICE_SECURE_OPEN
                                    , FALSE
                                    , &DeviceObject);

    if (!NT_SUCCESS(Status))
    {
        Log("[-] IoCreateDevice Fail... %u", Status);
        return Status;
    }

    if (!DeviceObject)
    {
        Log("[-] DeviceObject is Null. I/O Error...");
        return STATUS_UNEXPECTED_IO_ERROR;
    }
    Log("[+] IoCreateDevice success. Device : %.*ws", (unsigned int)(DeviceName.Length / sizeof(WCHAR)), DeviceName.Buffer);


    DeviceObject->Flags |= DO_BUFFERED_IO;
    DeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
    Status = IoCreateSymbolicLink(&Win32Device, &DeviceName);
    if (!NT_SUCCESS(Status))
    {
        Log("[-] IoCreateSymbolicLink Fail... %u", Status);
        return Status;
    }
    Log("[+] IoCreateSymbolicLink success. %.*ws -> %.*ws", (unsigned int)(Win32Device.Length / sizeof(WCHAR)), Win32Device.Buffer
                                                            , (unsigned int)(DeviceName.Length / sizeof(WCHAR)), DeviceName.Buffer);


    UNICODE_STRING RoutineName;
    RtlInitUnicodeString(&RoutineName, L"MmCopyVirtualMemory");
    MmCopyVirtualMemory = (MMCOPYVIRTUALMEMORY)MmGetSystemRoutineAddress(&RoutineName);
    if (!MmCopyVirtualMemory)
    {
        Log("[-] MmCopyVirtualMemory address not found ...");
        return STATUS_UNSUCCESSFUL;
    }

    Log("[+] DriverEntry Success");
    return STATUS_SUCCESS;
}