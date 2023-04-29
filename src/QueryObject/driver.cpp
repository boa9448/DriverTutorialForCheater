#include <ntifs.h>
#include <wdm.h>


#define log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[QueryObject]" "[" __FUNCTION__ "]" format "\n", __VA_ARGS__)


NTSTATUS query_object_name(HANDLE target_handle, POBJECT_NAME_INFORMATION* info)
{
    ULONG size = 0;
    OBJECT_INFORMATION_CLASS name_info_class = (OBJECT_INFORMATION_CLASS)1;
    NTSTATUS status = ZwQueryObject(target_handle, name_info_class, nullptr, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
    {
        log("ZwQueryObject failed with status: %X", status);
        return status;
    }

    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'reuq');
    if (buffer == nullptr)
    {
        log("ExAllocatePool2 failed");
        return STATUS_NO_MEMORY;
    }

    status = ZwQueryObject(target_handle, name_info_class, buffer, size, &size);
    if (!NT_SUCCESS(status))
    {
        log("ZwQueryObject failed with status: %X", status);
        ExFreePool(buffer);
        return status;
    }

    *info = (POBJECT_NAME_INFORMATION)buffer;
    return status;
}


void registry_handle_query()
{
    HANDLE key_handle = nullptr;
    UNICODE_STRING registry_path = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    OBJECT_ATTRIBUTES attr = { 0, };

    InitializeObjectAttributes(&attr, &registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    NTSTATUS status = ZwOpenKey(&key_handle, KEY_READ, &attr);
    if (!NT_SUCCESS(status))
    {
        log("ZwOpenKey failed with status: %X", status);
        return;
    }


    POBJECT_NAME_INFORMATION info = nullptr;
    status = query_object_name(key_handle, &info);
    if (!NT_SUCCESS(status))
    {
        log("query_object_name failed with status: %X", status);
        ZwClose(key_handle);
        return;
    }

    log("key name: %wZ", &info->Name);
    ExFreePool(info);
    ZwClose(key_handle);
}


void file_handle_query()
{
    HANDLE file_handle = nullptr;
    UNICODE_STRING file_path = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\ntdll.dll");
    OBJECT_ATTRIBUTES attr = { 0, };
    IO_STATUS_BLOCK io_status = { 0, };

    InitializeObjectAttributes(&attr, &file_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    NTSTATUS status = ZwCreateFile(&file_handle, FILE_READ_DATA, &attr, &io_status, nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
    if (!NT_SUCCESS(status))
    {
        log("ZwCreateFile failed with status: %X", status);
        return;
    }

    POBJECT_NAME_INFORMATION info = nullptr;
    status = query_object_name(file_handle, &info);
    if (!NT_SUCCESS(status))
    {
        log("query_object_name failed with status: %X", status);
        ZwClose(file_handle);
        return;
    }

    log("file name: %wZ", &info->Name);
    ExFreePool(info);
    ZwClose(file_handle);
}


void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    log("DriverUnload");
}


EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    log("Driver loaded");
    DriverObject->DriverUnload = DriverUnload;

    registry_handle_query();
    file_handle_query();
    log("DriverEntry finished");
    return STATUS_SUCCESS;
}