#include <ntddk.h>
#include <wdm.h>

#include "../communication_header.h"


#define Log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[CommunicationDriver]" format "\n", ##__VA_ARGS__);

UNICODE_STRING Win32Device;
UNICODE_STRING DeviceName;

CommunicationInfo LastData;


void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    Log("[+] DriverUnload call");
    IoDeleteSymbolicLink(&Win32Device);
    IoDeleteDevice(DriverObject->DeviceObject);
}


NTSTATUS DriverDefaultHandle(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}


NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Log("[+] DriverCreateClose call");

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

bool WriteProc(PVOID Buffer, ULONG Lenght)
{
    if (Lenght < sizeof(CommunicationInfo))
        return false;

    CommunicationInfo info = { 0, };
    memcpy(&info, Buffer, sizeof(info));

    Log("[+] WriteProc : x _ %d, y _ %d, z _ %d", info.x, info.y, info.z);
    LastData = info;

    return true;
}


NTSTATUS DriverWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Log("[+] DriverWrite call");

    ULONG_PTR WriteSize = sizeof(CommunicationInfo);;
    NTSTATUS Status = STATUS_SUCCESS;

    PIO_STACK_LOCATION IoStackIrp = IoGetCurrentIrpStackLocation(Irp);
    if (IoStackIrp)
    {
        PVOID Buffer = Irp->AssociatedIrp.SystemBuffer;
        if (Buffer)
        {
            if (WriteProc(Buffer, IoStackIrp->Parameters.Write.Length))
            {
                Log("[+] WriteProc Success!");
            }
            else
            {
                Log("[-] WriteProc Fail...");
                WriteSize = 0;
                Status = STATUS_UNSUCCESSFUL;
            }
        }
    }
    else
    {
        Log("[-] IoGetCurrentIrpStackLocation Fail...");
        WriteSize = 0;
        Status = STATUS_UNSUCCESSFUL;
    }

    Irp->IoStatus.Information = WriteSize;
    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    Log("[+] DriverWrite Success");
    return STATUS_SUCCESS;
}


bool ReadProc(PVOID Buffer, ULONG Lenght)
{
    if (Lenght < sizeof(CommunicationInfo))
        return false;

    memcpy(Buffer, &LastData, Lenght);
    Log("[+] ReadProc : x _ %d, y _ %d, z _ %d", LastData.x, LastData.y, LastData.z);

    return true;
}


NTSTATUS DriverRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Log("[+] DriverRead call");

    ULONG_PTR ReadSize = sizeof(CommunicationInfo);
    NTSTATUS Status = STATUS_SUCCESS;

    PIO_STACK_LOCATION IoStackIrp = IoGetCurrentIrpStackLocation(Irp);
    if (IoStackIrp)
    {
        PVOID Buffer = Irp->AssociatedIrp.SystemBuffer;
        if (ReadProc(Buffer, IoStackIrp->Parameters.Read.Length))
        {
            Log("[+] ReadProc Success!");
        }
        else
        {
            Log("[-] ReadProc Fail...");
            ReadSize = 0;
            Status = STATUS_UNSUCCESSFUL;
        }
    }
    else
    {
        Log("[-] IoGetCurrentIrpStackLocation Fail...");
        ReadSize = 0;
        Status = STATUS_UNSUCCESSFUL;
    }

    Irp->IoStatus.Information = ReadSize;
    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    Log("[+] DriverRead Success");
    return STATUS_SUCCESS;
}


extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    Log("[+] DriverEntry call");

    DriverObject->DriverUnload = DriverUnload;
    for (int idx = 0; idx < IRP_MJ_MAXIMUM_FUNCTION; idx++)
        DriverObject->MajorFunction[idx] = DriverDefaultHandle;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = DriverWrite;
    DriverObject->MajorFunction[IRP_MJ_READ] = DriverRead;

    RtlInitUnicodeString(&DeviceName, L"\\Device\\CommunicationDriver");
    RtlInitUnicodeString(&Win32Device, L"\\DosDevices\\CommunicationDriver");

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


    Log("[+] DriverEntry Success");
    return STATUS_SUCCESS;
}