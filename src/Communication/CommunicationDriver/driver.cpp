#include <ntddk.h>
#include <wdm.h>

#include "../communication_header.h"


#define Log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[HamsterDriver]" format "\n", ##__VA_ARGS__);

UNICODE_STRING Win32Device;
UNICODE_STRING DeviceName;


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


NTSTATUS DriverWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Log("[+] DriverWrite call");

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


NTSTATUS DriverRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Log("[+] DriverRead call");

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
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

    RtlInitUnicodeString(&DeviceName, L"\\Device\\HamsterDriver");
    RtlInitUnicodeString(&Win32Device, L"\\DosDevices\\HamsterDirver");

    PDEVICE_OBJECT DeviceObject = NULL;
    NTSTATUS status = IoCreateDevice(DriverObject
                                    , 0
                                    , &DeviceName
                                    , FILE_DEVICE_UNKNOWN
                                    , FILE_DEVICE_SECURE_OPEN
                                    , FALSE
                                    , &DeviceObject);

    if (!NT_SUCCESS(status))
    {
        Log("[-] IoCreateDevice Fail... %u", status);
        return status;
    }

    if (!DeviceObject)
    {
        Log("[-] DeviceObject is Null. I/O Error...");
        return STATUS_UNEXPECTED_IO_ERROR;
    }
    Log("[+] IoCreateDevice success. Device : %.*ws", (unsigned int)(DeviceName.Length / sizeof(WCHAR)), DeviceName.Buffer);


    DeviceObject->Flags |= DO_BUFFERED_IO;
    DeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
    status = IoCreateSymbolicLink(&Win32Device, &DeviceName);
    if (!NT_SUCCESS(status))
    {
        Log("[-] IoCreateSymbolicLink Fail... %u", status);
        return status;
    }
    Log("[+] IoCreateSymbolicLink success. %.*ws -> %.*ws", (unsigned int)(Win32Device.Length / sizeof(WCHAR)), Win32Device.Buffer
                                                            , (unsigned int)(DeviceName.Length / sizeof(WCHAR)), DeviceName.Buffer);


    Log("[+] DriverEntry Success");
    return STATUS_SUCCESS;
}