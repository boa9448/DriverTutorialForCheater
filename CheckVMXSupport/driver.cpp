#include <ntddk.h>
#include <wdm.h>
#include <intrin.h>


#define Log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[CheckVMXSupportDriver]" format "\n", ##__VA_ARGS__)

#define MSR_IA32_FEATURE_CONTROL 0x3A

typedef struct _CPUID
{
    int eax;
    int ebx;
    int ecx;
    int edx;
} CPUID, * PCPUID;


typedef union _IA32_FEATURE_CONTROL_MSR
{
    ULONG64 All;
    struct
    {
        ULONG64 Lock : 1;                           // [0]
        ULONG64 EnableVMXInsideSMX : 1;             // [1]
        ULONG64 EnableVMXOutsideSMX : 1;            // [2]
        ULONG64 Reserved1 : 5;                      // [3-7]
        ULONG64 SENTERLocalFunctionEnables : 7;     // [8-14]
        ULONG64 SENTERGlobalEnable : 1;             // [15]
        ULONG64 Reserved2 : 1;                      // [16]
        ULONG64 SGXLaunchControlEnable : 1;         // [17]
        ULONG64 SGXGlobalEnable : 1;                // [18]
        ULONG64 Reserved3 : 1;                      // [19]
        ULONG64 LMCEOn : 1;                         // [20]
        ULONG64 Reserved4 : 43;                     // [21-63]
    } Fields;
} IA32_FEATURE_CONTROL_MSR, * PIA32_FEATURE_CONTROL_MSR;


bool CheckVMXSupport()
{
    CPUID Data = { 0, };

    __cpuid((int*)&Data, 1);

    if (!_bittest((const LONG*)&Data.ecx, 5))
    {
        Log("[-] vmx not support... cpuid ecx 5bit false");
        return false;
    }

    IA32_FEATURE_CONTROL_MSR Control = { 0, };
    Control.All = __readmsr(MSR_IA32_FEATURE_CONTROL);

    if (Control.Fields.EnableVMXOutsideSMX == false)
    {
        Log("[-] vmx lock off in bios");
        return false;
    }

    return true;
}


void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    Log("[+] DriverUnload call");
}


extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;
    Log("[+] DriverEntry call");

    bool VmxSupport = CheckVMXSupport();
    if (VmxSupport)
        Log("[+] vmx support!");
    else
        Log("[-] vmx not support...");

    return STATUS_SUCCESS;
}