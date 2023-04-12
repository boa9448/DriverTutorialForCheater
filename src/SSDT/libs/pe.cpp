#include "global.hpp"
#include "pe.hpp"

namespace pe
{
    int rva_to_section(PIMAGE_NT_HEADERS nt_header, ULONG rva)
    {
        PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_header);
        for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++)
        {
            bool is_upper_min = section_header->VirtualAddress <= rva;
            bool is_lower_max = (section_header->VirtualAddress + section_header->Misc.VirtualSize) > rva;
            if (is_upper_min && is_lower_max)
                return i;

            section_header++;
        }

        log("[-] ssdt_index::rva_to_section fail...");
        return PE_ERROR;
    }

    int rva_to_offset(PIMAGE_NT_HEADERS nt_header, ULONG rva, ULONG file_size)
    {
        int section_index = rva_to_section(nt_header, rva);
        if (section_index == PE_ERROR)
        {
            log("[-] ssdt_index::rva_to_offset fail...");
            return PE_ERROR;
        }

        PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_header);
        section_header += section_index;

        ULONG offset = rva - section_header->VirtualAddress;
        offset += section_header->PointerToRawData;

        return offset > file_size ? PE_ERROR : offset;
    }

    PVOID get_page_base(PVOID file_buffer, ULONG* page_size, PVOID func_addr)
    {
        if (func_addr < file_buffer)
        {
            log("[-] ssdt_index::get_page_base func_addr < file_buffer");
            return nullptr;
        }

        ULONG rva = (ULONG)((ULONG_PTR)func_addr - (ULONG_PTR)file_buffer);
        PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)file_buffer;
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
        {
            log("[-] ssdt_index::get_page_base dos_header->e_magic != IMAGE_DOS_SIGNATURE");
            return nullptr;
        }

        PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((ULONG_PTR)file_buffer + dos_header->e_lfanew);
        if (nt_header->Signature != IMAGE_NT_SIGNATURE)
        {
            log("[-] ssdt_index::get_page_base nt_header->Signature != IMAGE_NT_SIGNATURE");
            return nullptr;
        }

        PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_header);
        int section_index = rva_to_section(nt_header, rva);
        if (section_index == PE_ERROR)
        {
            log("[-] ssdt_index::get_page_base rva_to_section fail...");
            return nullptr;
        }

        if(page_size)
            *page_size = section_header[section_index].SizeOfRawData;

        return (PVOID)((ULONG_PTR)file_buffer + section_header[section_index].VirtualAddress);
    }

    ULONG get_export_offset(LPCSTR export_func_name, PVOID file_buffer, ULONG file_size)
    {
        PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)file_buffer;
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
        {
            log("[-] ssdt_index::get_export_offset dos_header->e_magic != IMAGE_DOS_SIGNATURE");
            return PE_ERROR;
        }

        PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((ULONG_PTR)file_buffer + dos_header->e_lfanew);
        if (nt_header->Signature != IMAGE_NT_SIGNATURE)
        {
            log("[-] ssdt_index::get_export_offset nt_header->Signature != IMAGE_NT_SIGNATURE");
            return PE_ERROR;
        }

        PIMAGE_DATA_DIRECTORY export_data_dir = &nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        ULONG export_rva = export_data_dir->VirtualAddress;
        ULONG export_size = export_data_dir->Size;
        ULONG export_dir_offset = rva_to_offset(nt_header, export_rva, file_size);
        if (export_dir_offset == PE_ERROR)
        {
            log("[-] ssdt_index::get_export_offset export_data_offset == PE_ERROR");
            return PE_ERROR;
        }

        PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)file_buffer + export_dir_offset);
        ULONG number_of_names = export_dir->NumberOfNames;
        ULONG address_of_functions_offset = rva_to_offset(nt_header, export_dir->AddressOfFunctions, file_size);
        ULONG address_of_names_offset = rva_to_offset(nt_header, export_dir->AddressOfNames, file_size);
        ULONG address_of_name_ordinals_offset = rva_to_offset(nt_header, export_dir->AddressOfNameOrdinals, file_size);
        if (address_of_functions_offset == PE_ERROR
            || address_of_names_offset == PE_ERROR
            || address_of_name_ordinals_offset == PE_ERROR)
        {
            log("[-] ssdt_index::get_export_offset export_dir_offset fail...");
            return PE_ERROR;
        }

        ULONG* address_of_functions = (ULONG*)((ULONG_PTR)file_buffer + address_of_functions_offset);
        ULONG* address_of_names = (ULONG*)((ULONG_PTR)file_buffer + address_of_names_offset);
        USHORT* address_of_name_ordinals = (USHORT*)((ULONG_PTR)file_buffer + address_of_name_ordinals_offset);

        for (ULONG idx = 0; idx < number_of_names; idx++)
        {
            ULONG current_name_offset = rva_to_offset(nt_header, address_of_names[idx], file_size);
            if (current_name_offset == PE_ERROR)
            {
                log("[-] ssdt_index::get_export_offset current_name_offset == PE_ERROR");
                return PE_ERROR;
            }

            LPCSTR current_name = (LPCSTR)((ULONG_PTR)file_buffer + current_name_offset);
            ULONG current_func_rva = address_of_functions[address_of_name_ordinals[idx]];
            if (current_func_rva >= export_rva && current_func_rva < export_rva + export_size)
                continue;

            if (strcmp(current_name, export_func_name) == 0)
            {
                return rva_to_offset(nt_header, current_func_rva, file_size);
            }
        }

        log("[-] ssdt_index::get_export_offset not found...");
        return PE_ERROR;
    }
}