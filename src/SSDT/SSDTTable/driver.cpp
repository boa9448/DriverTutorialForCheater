#include "../libs/global.hpp"
#include "../libs/ssdt_index.hpp"
#include "../libs/ssdt.hpp"


void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    ssdt_index::terminate();
    log("[ ] Driver unloaded");
}


EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;

    if (!ssdt_index::init())
    {
        log("[-] Failed to initialize SSDTIndex");
        return STATUS_UNSUCCESSFUL;
    }

    if (!ssdt::init())
    {
        log("[-] Failed to initialize SSDT");
        return STATUS_UNSUCCESSFUL;
    }

    log("[+] NtOpenProcess addr : 0x%p", ssdt::get_ssdt_function_addr("NtOpenProcess"));
    log("[+] NtQuerySystemInformation addr : 0x%p", ssdt::get_ssdt_function_addr("NtQuerySystemInformation"));
    log("[+] NtCreateFile addr : 0x%p", ssdt::get_ssdt_function_addr("NtCreateFile"));

    if (ssdt::attach_winlogon())
    {
        //ssdt shadow table
        log("[+] NtUserGetForegroundWindow addr : 0x%p", ssdt::get_ssdt_shadow_function_addr("NtUserGetForegroundWindow"));

        // 없는 함수 이름을 찾으려고 시도함
        log("[-] NtMyFunction addr : 0x%p", ssdt::get_ssdt_function_addr("NtMyFunction"));
        log("[-] NtMyFunction addr : 0x%p", ssdt::get_ssdt_shadow_function_addr("NtMyFunction"));

        ssdt::detach_winlogon();
    }

    log("[+] SSDT DriverEntry initialized");
    return STATUS_SUCCESS;
}