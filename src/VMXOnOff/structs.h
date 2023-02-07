#pragma once
#include <wdm.h>


#pragma pack(push, 4)
typedef struct _CPUID
{
    int eax;
    int ebx;
    int ecx;
    int edx;
} CPUID, * PCPUID;
#pragma pack(pop)


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



typedef struct _VIRTUAL_MACHINE_STATE
{
    UINT64 VmxonRegion;
    UINT64 VmcsRegion;
} VIRTUAL_MACHINE_STATE, *PVIRTUAL_MACHINE_STATE;


typedef union _IA32_VMX_BASIC_MSR
{
    ULONG64 All;
    struct
    {
        ULONG32 RevisionIdentifier : 31;  // [0-30]
        ULONG32 Reserved1 : 1;            // [31]
        ULONG32 RegionSize : 12;          // [32-43]
        ULONG32 RegionClear : 1;          // [44]
        ULONG32 Reserved2 : 3;            // [45-47]
        ULONG32 SupportedIA64 : 1;        // [48]
        ULONG32 SupportedDualMoniter : 1; // [49]
        ULONG32 MemoryType : 4;           // [50-53]
        ULONG32 VmExitReport : 1;         // [54]
        ULONG32 VmxCapabilityHint : 1;    // [55]
        ULONG32 Reserved3 : 8;            // [56-63]
    } Fields;
} IA32_VMX_BASIC_MSR, * PIA32_VMX_BASIC_MSR;