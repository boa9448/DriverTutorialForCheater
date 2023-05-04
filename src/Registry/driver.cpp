#include <ntifs.h>
#include <wdm.h>

#define log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Registry]" "[" __FUNCTION__ "]" format "\n", __VA_ARGS__)


void read_registry()
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

    ULONG size = 0;
    UNICODE_STRING value_name = RTL_CONSTANT_STRING(L"ProductName");
    status = ZwQueryValueKey(key_handle, &value_name, KeyValuePartialInformation, nullptr, 0, &size);
    if (status != STATUS_BUFFER_TOO_SMALL)
    {
        log("ZwQueryValueKey failed with status: %X", status);
        ZwClose(key_handle);
        return;
    }

    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'iger');
    if (info == nullptr)
    {
        log("ExAllocatePool2 failed");
        ZwClose(key_handle);
        return;
    }

    status = ZwQueryValueKey(key_handle, &value_name, KeyValuePartialInformation, info, size, &size);
    if (!NT_SUCCESS(status))
    {
        log("ZwQueryValueKey failed with status: %X", status);
        ExFreePool(info);
        ZwClose(key_handle);
        return;
    }

    UNICODE_STRING value = { 0, };
    USHORT length = (USHORT)info->DataLength;
    value.Length = length;
    value.MaximumLength = length;
    value.Buffer = (PWCH)info->Data;

    log("current window product name: %wZ", &value);
    ZwClose(key_handle);
}


void enum_registry()
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


    ULONG size = 0;
    for (ULONG idx = 0;; idx++)
    {
        status = ZwEnumerateValueKey(key_handle, idx, KeyValueFullInformation, nullptr, 0, &size);
        if (status == STATUS_NO_MORE_ENTRIES)
        {
            log("ZwEnumerateValueKey finished");
            break;
        }

        if(status != STATUS_BUFFER_TOO_SMALL)
        {
            log("ZwEnumerateValueKey failed with status: %X", status);
            break;
        }

        PKEY_VALUE_FULL_INFORMATION info = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'iger');
        if (info == nullptr)
        {
            log("ExAllocatePool2 failed");
            break;
        }

        status = ZwEnumerateValueKey(key_handle, idx, KeyValueFullInformation, info, size, &size);
        if (!NT_SUCCESS(status))
        {
            log("ZwEnumerateValueKey failed with status: %X", status);
            ExFreePool(info);
            break;
        }

        UNICODE_STRING value_name = { 0, };
        USHORT length = (USHORT)info->NameLength;
        value_name.Length = length;
        value_name.MaximumLength = length;
        value_name.Buffer = (PWCH)info->Name;

        UNICODE_STRING value = { 0, };
        length = (USHORT)info->DataLength;
        value.Length = length;
        value.MaximumLength = length;
        value.Buffer = (PWCH)((PUCHAR)info + info->DataOffset);

        log("%wZ: %wZ", &value_name, &value);
        ExFreePool(info);
    }

    log("enum registry finished");
    ZwClose(key_handle);
}


void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    log("Driver unloaded");
}


EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    log("Driver loaded");

    DriverObject->DriverUnload = DriverUnload;

    read_registry();
    enum_registry();

    log("Driver entry finished");
    return STATUS_SUCCESS;
}