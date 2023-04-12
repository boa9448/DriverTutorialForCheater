#include "global.hpp"
#include "ssdt_index.hpp"


void DriverUnload(PDRIVER_OBJECT driver_object)
{
    UNREFERENCED_PARAMETER(driver_object);
    ssdt_index::terminate();
    log("[ ] SSDTIndex terminated");
}


EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
    UNREFERENCED_PARAMETER(registry_path);
    driver_object->DriverUnload = DriverUnload;

    if (!ssdt_index::init())
    {
        log("[-] Failed to initialize SSDTIndex");
        return STATUS_UNSUCCESSFUL;
    }

    log("[+] NtOpenProcess index : %d", ssdt_index::get_export_ssdt_index("NtOpenProcess"));
    log("[+] NtQuerySystemInformation index : %d", ssdt_index::get_export_ssdt_index("NtQuerySystemInformation"));
    log("[+] NtCreateFile index : %d", ssdt_index::get_export_ssdt_index("NtCreateFile"));

    //ssdt shadow table
    log("[+] NtUserGetForegroundWindow index : %d", ssdt_index::get_export_ssdt_shadow_index("NtUserGetForegroundWindow"));

    // 없는 함수 이름을 찾으려고 시도함
    log("[-] NtMyFunction index : %d", ssdt_index::get_export_ssdt_index("NtMyFunction"));
    log("[-] NtMyFunction index : %d", ssdt_index::get_export_ssdt_shadow_index("NtMyFunction"));

    log("[+] SSDTIndex DriverEntry initialized");
    return STATUS_SUCCESS;
}