#pragma once
#include "global.hpp"


namespace ssdt
{
    PVOID get_ssdt_function_addr(LPCSTR func_name);
    PVOID get_ssdt_shadow_function_addr(LPCSTR func_name);

    bool attach_winlogon();
    void detach_winlogon();
    bool init();
}