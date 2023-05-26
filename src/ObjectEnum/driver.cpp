#include <ntddk.h>
#include <wdm.h>


#define log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ObjectEnum]" "[" __FUNCTION__ "]" format "\n", __VA_ARGS__)


typedef NTSTATUS NTAPI ZwOpenDirectoryObject(
    OUT PHANDLE DirectoryHandle,
    IN  ACCESS_MASK DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes
);


typedef NTSTATUS NTAPI ZwQueryDirectoryObject(
    IN  HANDLE DirectoryHandle,
    OUT PVOID Buffer,
    IN  ULONG Length,
    IN  BOOLEAN ReturnSingleEntry,
    IN  BOOLEAN RestartScan,
    IN OUT PULONG Context,
    OUT PULONG ReturnLength OPTIONAL
);


typedef struct _OBJECT_DIRECTORY_INFORMATION
{
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;


typedef NTSTATUS(NTAPI* ZWOPENDIRECTORYOBJECT)(
    OUT PHANDLE DirectoryHandle,
    IN  ACCESS_MASK DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes
);


typedef NTSTATUS(NTAPI* ZWQUERYDIRECTORYOBJECT)(
    IN  HANDLE DirectoryHandle,
    OUT PVOID Buffer,
    IN  ULONG Length,
    IN  BOOLEAN ReturnSingleEntry,
    IN  BOOLEAN RestartScan,
    IN OUT PULONG Context,
    OUT PULONG ReturnLength OPTIONAL
);



ZWOPENDIRECTORYOBJECT fp_ZwOpenDirectoryObject = nullptr;
ZWQUERYDIRECTORYOBJECT fp_ZwQueryDirectoryObject = nullptr;


bool init_function()
{
    UNICODE_STRING func_name = RTL_CONSTANT_STRING(L"ZwOpenDirectoryObject");
    fp_ZwOpenDirectoryObject = (ZWOPENDIRECTORYOBJECT)MmGetSystemRoutineAddress(&func_name);
    if (!fp_ZwOpenDirectoryObject)
    {
        log("MmGetSystemRoutineAddress failed: ZwOpenDirectoryObject");
        return false;
    }

    func_name = RTL_CONSTANT_STRING(L"ZwQueryDirectoryObject");
    fp_ZwQueryDirectoryObject = (ZWQUERYDIRECTORYOBJECT)MmGetSystemRoutineAddress(&func_name);
    if (!fp_ZwQueryDirectoryObject)
    {
        log("MmGetSystemRoutineAddress failed: ZwQueryDirectoryObject");
        return false;
    }

    return true;
}


void enum_object(LPCWSTR object_namespace)
{
    log("========= enum object: %ws =========", object_namespace);
    HANDLE dir_handle = nullptr;
    UNICODE_STRING namespace_name = { 0, };
    OBJECT_ATTRIBUTES attr = { 0, };

    RtlInitUnicodeString(&namespace_name, object_namespace);
    InitializeObjectAttributes(
        &attr
        , &namespace_name
        , OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE
        , NULL
        , NULL);

    NTSTATUS status = fp_ZwOpenDirectoryObject(&dir_handle, DIRECTORY_QUERY, &attr);
    if (!NT_SUCCESS(status))
    {
        log("ZwOpenDirectoryObject failed: 0x%X", status);
        return;
    }

    ULONG size = 1024;
    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'mune');
    if (!buffer)
    {
        log("ExAllocatePool2 failed");
        ZwClose(dir_handle);
        return;
    }

    ULONG context = 0;
    ULONG return_length = 0;
    while (true)
    {
        status = fp_ZwQueryDirectoryObject(dir_handle, buffer, size, FALSE, FALSE, &context, &return_length);
        if (!NT_SUCCESS(status))
        {
            if (status == STATUS_NO_MORE_ENTRIES)
                log("ZwQueryDirectoryObject finished");
            else
                log("ZwQueryDirectoryObject failed: 0x%X", status);

            break;
        }

        POBJECT_DIRECTORY_INFORMATION info = (POBJECT_DIRECTORY_INFORMATION)buffer;
        for (;;)
        {
            if (info->Name.Length == 0)
                break;

            log("%ws : %wZ (%wZ)", object_namespace, &info->Name, &info->TypeName);
            info++;
        }
    }

    ExFreePool(buffer);
    ZwClose(dir_handle);
}


void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    log("driver unload");
}


EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    log("driver load");

    DriverObject->DriverUnload = DriverUnload;

    if (!init_function())
    {
        log("init_function failed");
        return STATUS_UNSUCCESSFUL;
    }

    enum_object(L"\\");
    enum_object(L"\\GLOBAL??");
    enum_object(L"\\Driver");
    enum_object(L"\\Device");

    log("driver entry finished");
    return STATUS_SUCCESS;
}