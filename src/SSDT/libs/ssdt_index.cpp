#include "global.hpp"
#include "pe.hpp"
#include "ssdt_index.hpp"

namespace ssdt_index
{
    PVOID g_ntdll_buffer = nullptr;
    ULONG g_ntdll_size = 0;
    PVOID g_win32u_buffer = nullptr;
    ULONG g_win32u_size = 0;


    NTSTATUS load_file(LPCWSTR file_path, PVOID* file_data, ULONG* file_size)
    {
        UNICODE_STRING u_file_path = { 0, };
        RtlInitUnicodeString(&u_file_path, file_path);

        OBJECT_ATTRIBUTES attr = { 0, };
        InitializeObjectAttributes(&attr
            , &u_file_path
            , OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE
            , NULL
            , NULL);

        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        {
            log("[-] KeGetCurrentIrql != PASSIVE_LEVEL");
            return STATUS_UNSUCCESSFUL;
        }

        HANDLE file_handle = NULL;
        IO_STATUS_BLOCK io_status = { 0 , };
        NTSTATUS status = ZwCreateFile(&file_handle
            , GENERIC_READ
            , &attr
            , &io_status
            , NULL
            , FILE_ATTRIBUTE_NORMAL
            , FILE_SHARE_READ
            , FILE_OPEN
            , FILE_SYNCHRONOUS_IO_NONALERT
            , NULL
            , 0);

        if (!NT_SUCCESS(status))
        {
            log("[-] ZwCreateFile fail... 0x%x", status);
            return status;
        }

        FILE_STANDARD_INFORMATION file_info = { 0, };
        status = ZwQueryInformationFile(file_handle
            , &io_status
            , &file_info
            , sizeof(FILE_STANDARD_INFORMATION)
            , FileStandardInformation);

        if (!NT_SUCCESS(status))
        {
            log("[-] ZwQueryInformationFile fail... 0x%x", status);
            ZwClose(file_handle);
            return status;
        }

        ULONG dll_file_size = file_info.EndOfFile.LowPart;
        log("[+] file size: %d", dll_file_size);

        PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, dll_file_size, 'smaH');
        if (!buffer)
        {
            log("[-] ExAllocatePool2 fail...");
            ZwClose(file_handle);
            return STATUS_UNSUCCESSFUL;
        }

        LARGE_INTEGER byte_offset = { 0, };
        byte_offset.QuadPart = 0;

        status = ZwReadFile(file_handle, NULL, NULL, NULL, &io_status, buffer, dll_file_size, &byte_offset, NULL);
        if (!NT_SUCCESS(status))
        {
            log("[-] ZwReadFile fail... 0x%x", status);
            ExFreePool(buffer);
            ZwClose(file_handle);
            return status;
        }

        *file_data = buffer;
        *file_size = dll_file_size;
        return status;
    }


    int get_export_index(LPCSTR func_name, PVOID dll_buffer, ULONG dll_buffer_size)
    {
        ULONG_PTR export_offset = pe::get_export_offset(func_name, dll_buffer, dll_buffer_size);
        if (export_offset == pe::PE_ERROR)
        {
            log("[-] ssdt_index::get_export_index get_export_offset fail...");
            return SSDT_INDEX_ERROR;
        }

        int export_idx = -1;
        unsigned char* export_data = (unsigned char*)((UINT_PTR)dll_buffer + export_offset);
        for (int idx = 0; idx < 32 && export_offset + idx < dll_buffer_size; idx++)
        {
            if (export_data[idx] == 0xC2 || export_data[idx] == 0xC3) // RET
                break;

            if (export_data[idx] == 0xB8) // mov eax, X
            {
                export_idx = *(int*)(export_data + idx + 1);
                break;
            }
        }

        if (export_idx == -1)
            log("[-] ssdt index for %s not found...", func_name);

        return export_idx;
    }

    int get_export_ssdt_index(LPCSTR func_name)
    {
        return get_export_index(func_name, g_ntdll_buffer, g_ntdll_size);
    }

    int get_export_ssdt_shadow_index(LPCSTR func_name)
    {
        int idx = get_export_index(func_name, g_win32u_buffer, g_win32u_size);
        if (idx == SSDT_INDEX_ERROR)
            return SSDT_INDEX_ERROR;

        idx -= 0x1000;
        return idx;
    }

    bool init()
    {
        NTSTATUS status = load_file(L"\\SystemRoot\\System32\\ntdll.dll", &g_ntdll_buffer, &g_ntdll_size);
        if (!NT_SUCCESS(status))
        {
            log("[-] load_file fail... 0x%x", status);
            return false;
        }

        status = load_file(L"\\SystemRoot\\System32\\win32u.dll", &g_win32u_buffer, &g_win32u_size);
        if (!NT_SUCCESS(status))
        {
            ExFreePool(g_ntdll_buffer);
            g_ntdll_buffer = nullptr;

            log("[-] load_file fail... 0x%x", status);
            return false;
        }

        log("[+] ssdt_index::init success!");
        return true;
    }

    void terminate()
    {
        if (g_ntdll_buffer)
        {
            ExFreePool(g_ntdll_buffer);
            g_ntdll_buffer = nullptr;
        }

        if (g_win32u_buffer)
        {
            ExFreePool(g_win32u_buffer);
            g_win32u_buffer = nullptr;
        }

        log("[+] ssdt_index::terminate success!");
    }

}