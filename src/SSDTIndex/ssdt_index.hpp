#pragma once
#include <ntimage.h>
#include "global.hpp"


namespace ssdt_index
{
    constexpr ULONG PE_ERROR = (ULONG) - 1;

    int get_export_ssdt_index(LPCSTR func_name);
    int get_export_ssdt_shadow_index(LPCSTR func_name);

    bool init();
    void terminate();
}