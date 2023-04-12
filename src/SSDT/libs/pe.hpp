#pragma once
#include <ntimage.h>
#include "global.hpp"


namespace pe
{
    constexpr ULONG PE_ERROR = (ULONG) -1;

    int rva_to_section(PIMAGE_NT_HEADERS nt_header, ULONG rva);
    int rva_to_offset(PIMAGE_NT_HEADERS nt_header, ULONG rva, ULONG file_size);
    PVOID get_page_base(PVOID file_buffer, ULONG* page_size, PVOID func_addr);
    ULONG get_export_offset(LPCSTR export_func_name, PVOID file_buffer, ULONG file_size);
}