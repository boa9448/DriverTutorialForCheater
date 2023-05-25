#include <ntifs.h>
#include <wdm.h>


#define log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[File]" "[" __FUNCTION__ "]" format "\n", __VA_ARGS__)


UNICODE_STRING g_file_name = RTL_CONSTANT_STRING(L"\\DosDevices\\C:\\test.txt");
void file_write()
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        log("KeGetCurrentIrql is not PASSIVE_LEVEL");
        return;
    }

    OBJECT_ATTRIBUTES attr = { 0, };
    InitializeObjectAttributes(&attr
        , &g_file_name
        , OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE
        , NULL
        , NULL);

    HANDLE file_handle = nullptr;
    IO_STATUS_BLOCK io_status_block = { 0, };
    NTSTATUS status = ZwCreateFile(
        &file_handle
        , FILE_WRITE_DATA
        , &attr
        , &io_status_block
        , NULL
        , FILE_ATTRIBUTE_NORMAL
        , FILE_SHARE_READ
        , FILE_SUPERSEDE
        , FILE_SYNCHRONOUS_IO_NONALERT
        , NULL
        , 0);

    if (!NT_SUCCESS(status))
    {
        log("ZwCreateFile failed: 0x%X", status);
        return;
    }

    char buffer[] = { "Hello, World!\r\n" };
    ZwWriteFile(file_handle, NULL, NULL, NULL, &io_status_block, buffer, sizeof(buffer), NULL, NULL);
    ZwClose(file_handle);
}

void file_read()
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        log("KeGetCurrentIrql is not PASSIVE_LEVEL");
        return;
    }

    OBJECT_ATTRIBUTES attr = { 0, };
    InitializeObjectAttributes(
        &attr
        , &g_file_name
        , OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE
        , NULL
        , NULL);

    HANDLE file_handle = nullptr;
    IO_STATUS_BLOCK io_status_block = { 0, };
    NTSTATUS status = ZwCreateFile(
        &file_handle
        , FILE_READ_DATA
        , &attr
        , &io_status_block
        , NULL
        , FILE_ATTRIBUTE_NORMAL
        , FILE_SHARE_READ
        , FILE_OPEN
        , FILE_SYNCHRONOUS_IO_NONALERT
        , NULL
        , 0);

    if (!NT_SUCCESS(status))
    {
        log("ZwCreateFile failed: 0x%X", status);
        return;
    }

    char buffer[255] = { 0, };
    status = ZwReadFile(file_handle, NULL, NULL, NULL, &io_status_block, buffer, sizeof(buffer), NULL, NULL);
    if (!NT_SUCCESS(status))
    {
        log("ZwReadFile failed: 0x%X", status);
        ZwClose(file_handle);
        return;
    }

    log("buffer: %s", buffer);
    ZwClose(file_handle);
}

void enum_directory(LPCWSTR file_pattern)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        log("KeGetCurrentIrql is not PASSIVE_LEVEL");
        return;
    }

    UNICODE_STRING folder_name = RTL_CONSTANT_STRING(L"\\DosDevices\\C:\\");
    OBJECT_ATTRIBUTES atrr = { 0, };
    InitializeObjectAttributes(
        &atrr
        , &folder_name
        , OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE
        , NULL
        , NULL);

    HANDLE folder_handle = nullptr;
    IO_STATUS_BLOCK io_status_block = { 0, };
    NTSTATUS status = ZwCreateFile(
        &folder_handle
        , FILE_LIST_DIRECTORY | SYNCHRONIZE
        , &atrr
        , &io_status_block
        , NULL
        , FILE_ATTRIBUTE_NORMAL
        , FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        , FILE_OPEN
        , FILE_SYNCHRONOUS_IO_NONALERT
        , NULL
        , 0);

    if (!NT_SUCCESS(status))
    {
        log("ZwCreateFile failed: 0x%X", status);
        return;
    }

    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, 512, 'elif');
    if (!buffer)
    {
        log("ExAllocatePoolWithTag failed");
        ZwClose(folder_handle);
        return;
    }
    
    log("===== file pattern: %ws =====", file_pattern);
    PFILE_DIRECTORY_INFORMATION info = nullptr;
    UNICODE_STRING pattern = { 0, };
    UNICODE_STRING file_name = { 0, };

    RtlInitUnicodeString(&pattern, file_pattern);
    while (true)
    {
        info = (PFILE_DIRECTORY_INFORMATION)buffer;
        status = ZwQueryDirectoryFile(
            folder_handle
            , NULL
            , NULL
            , NULL
            , &io_status_block
            , info
            , 512
            , FileDirectoryInformation
            , FALSE
            , &pattern
            , FALSE);

        if (!NT_SUCCESS(status))
        {
            if(status != STATUS_NO_MORE_FILES)
                log("ZwQueryDirectoryFile failed: 0x%X", status);
            else
                log("ZwQueryDirectoryFile finished");

            break;
        }

        while (true)
        {
            file_name.Length = (USHORT)info->FileNameLength;
            file_name.MaximumLength = (USHORT)info->FileNameLength;
            file_name.Buffer = info->FileName;

            log("file name: %wZ", &file_name);

            if (info->NextEntryOffset == 0)
                break;

            info = (PFILE_DIRECTORY_INFORMATION)((UINT_PTR)info + info->NextEntryOffset);
        }
    }


    ExFreePool(buffer);
    ZwClose(folder_handle);
}


void delete_file()
{
    OBJECT_ATTRIBUTES attr = { 0, };
    InitializeObjectAttributes(
        &attr
        , &g_file_name
        , OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE
        , NULL
        , NULL);

    NTSTATUS status = ZwDeleteFile(&attr);
    if (!NT_SUCCESS(status))
    {
        log("ZwDeleteFile failed: 0x%X", status);
        return;
    }

    log("file deleted");
}

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    log("driver unloaded");
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    log("driver loaded");

    DriverObject->DriverUnload = DriverUnload;

    file_write();
    file_read();
    enum_directory(L"*");
    enum_directory(L"*.txt");
    delete_file();

    log("driver entry finished");
    return STATUS_SUCCESS;
}