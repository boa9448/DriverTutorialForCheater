//https://rayanfam.com/topics/hypervisor-from-scratch-part-3/

#include <ntddk.h>
#include <wdm.h>
#include <intrin.h>

#include "structs.h"

//4K 단위로 정렬되어야함
#define ALIGNMENT_PAGE_SIZE 4096
#define VMXON_SIZE          4096
#define VMCS_SIZE           4096

#define MSR_IA32_VMX_BASIC  0x480

#define MSR_IA32_FEATURE_CONTROL 0x3A
#define Log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[VMXOnOff]" format "\n", ##__VA_ARGS__)


extern "C" void AsmEnableVmxOperation();

UNICODE_STRING Win32Device;
UNICODE_STRING DeviceName;

VIRTUAL_MACHINE_STATE* g_GuestState = NULL;

BOOLEAN CheckVMXSupport()
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


INT MathPower(INT Base, INT Exp)
{
    INT Result = 1;
    for (;;)
    {
        if (Exp & 1)
            Result *= Base;

        Exp >>= 1;
        if (!Exp)
            break;

        Base *= Base;
    }

    return Result;
}


UINT64 VirtualToPhysicalAddress(PVOID Address)
{
    return MmGetPhysicalAddress(Address).QuadPart;
}


PVOID PhysicalToVirtualAddress(UINT64 Address)
{
    PHYSICAL_ADDRESS PhysicalAddress;
    PhysicalAddress.QuadPart = Address;

    return MmGetVirtualForPhysical(PhysicalAddress);
}


BOOLEAN AllocateVMXOnRegion(VIRTUAL_MACHINE_STATE* GuestState)
{
    //MmAllocateContiguousMemory 함수의 IRQL이 IRQL <= DISPATCH_LEVEL임
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        KeRaiseIrqlToDpcLevel();

    PHYSICAL_ADDRESS PhysicalMax = { 0, };
    PhysicalMax.QuadPart = MAXULONG64;

    SIZE_T VMXOnSize = 2 * VMXON_SIZE;
    PVOID Buffer = MmAllocateContiguousMemory(VMXOnSize + ALIGNMENT_PAGE_SIZE, PhysicalMax);

    if (Buffer == NULL)
    {
        Log("[-] VMXON Region buffer is NULL. MmAllocateContiguousMemory fail");
        return false;
    }


    PHYSICAL_ADDRESS Highest = { 0, }, Lowest = { 0, };
    Highest.QuadPart = ~0;

    UINT64 PhysicalBuffer = VirtualToPhysicalAddress(Buffer);

    //MmAllocateContiguousMemory가 할당하는 메모리는 직접 0으로 초기화해야함
    RtlSecureZeroMemory(Buffer, VMXOnSize + ALIGNMENT_PAGE_SIZE);
    UINT64 AlignedPhysicalBuffer = (PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1);
    UINT64 AlignedVirtualBuffer = ((UINT64)Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1);

    Log("[+] Virtual allocated buffer for VMXON at %llx", (UINT64)Buffer);
    Log("[+] VIrtual aligned allocated buffer for VMXON at %llx", AlignedVirtualBuffer);
    Log("[+] Aligned Physical buffer allocated for VMXON at %llx", AlignedPhysicalBuffer);

    IA32_VMX_BASIC_MSR Basic = { 0, };

    Basic.All = __readmsr(MSR_IA32_VMX_BASIC);
    Log("[+] MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %x", Basic.Fields.RevisionIdentifier);

    *(UINT64*)AlignedVirtualBuffer = Basic.Fields.RevisionIdentifier;

    INT Status = __vmx_on(&AlignedPhysicalBuffer);
    if (Status)
    {
        Log("[+] VMXON failed with status %d", Status);
        return false;
    }

    GuestState->VmxonRegion = AlignedPhysicalBuffer;
    return true;
}


BOOLEAN AllocateVMCSRegion(VIRTUAL_MACHINE_STATE* GuestState)
{
    //MmAllocateContiguousMemory 함수의 IRQL이 IRQL <= DISPATCH_LEVEL임
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        KeRaiseIrqlToDpcLevel();

    PHYSICAL_ADDRESS PhysicalMax = { 0, };
    PhysicalMax.QuadPart = MAXULONG64;

    SIZE_T VMXOnSize = 2 * VMXON_SIZE;
    PVOID Buffer = MmAllocateContiguousMemory(VMXOnSize + ALIGNMENT_PAGE_SIZE, PhysicalMax);

    if (Buffer == NULL)
    {
        Log("[-] VMXON Region buffer is NULL. MmAllocateContiguousMemory fail");
        return false;
    }


    PHYSICAL_ADDRESS Highest = { 0, }, Lowest = { 0, };
    Highest.QuadPart = ~0;

    UINT64 PhysicalBuffer = VirtualToPhysicalAddress(Buffer);

    //MmAllocateContiguousMemory가 할당하는 메모리는 직접 0으로 초기화해야함
    RtlSecureZeroMemory(Buffer, VMXOnSize + ALIGNMENT_PAGE_SIZE);
    UINT64 AlignedPhysicalBuffer = (PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1);
    UINT64 AlignedVirtualBuffer = ((UINT64)Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1);

    Log("[+] Virtual allocated buffer for VMCS at %llx", (UINT64)Buffer);
    Log("[+] VIrtual aligned allocated buffer for VMCS at %llx", AlignedVirtualBuffer);
    Log("[+] Aligned Physical buffer allocated for VMCS at %llx", AlignedPhysicalBuffer);

    IA32_VMX_BASIC_MSR Basic = { 0, };

    Basic.All = __readmsr(MSR_IA32_VMX_BASIC);
    Log("[+] MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %x", Basic.Fields.RevisionIdentifier);

    *(UINT64*)AlignedVirtualBuffer = Basic.Fields.RevisionIdentifier;

    INT Status = __vmx_vmptrld(&AlignedPhysicalBuffer);
    if (Status)
    {
        Log("[+] VMCS failed with status %d", Status);
        return false;
    }

    GuestState->VmcsRegion = AlignedPhysicalBuffer;
    return true;
}


BOOLEAN InitVMX()
{
    if (!CheckVMXSupport())
    {
        Log("[-] CheckVMXSupport false");
        return false;
    }

    KAFFINITY AffinityMask = 0;
    INT ProcessCount = KeQueryActiveProcessorCount(NULL);

    g_GuestState = (VIRTUAL_MACHINE_STATE*)ExAllocatePoolWithTag(NonPagedPool
                                                                , sizeof(VIRTUAL_MACHINE_STATE) * ProcessCount
                                                                , 'smaH');

    if (g_GuestState == NULL)
    {
        Log("[-] InitVMX ExAllocatePoolWithTag fail...");
        return false;
    }


    for (int idx = 0; idx < ProcessCount; idx++)
    {
        AffinityMask = MathPower(2, idx);
        KeSetSystemAffinityThread(AffinityMask);

        Log("=====================================================");
        Log("[+] Current Thread is executing in %d th logical processor", idx);

        AsmEnableVmxOperation();
        Log("[+] VMX Operation Enabled Successfully !");

        AllocateVMXOnRegion(&g_GuestState[idx]);
        AllocateVMCSRegion(&g_GuestState[idx]);

        Log("[+] VMCS Region is allocated at  ===============> %llx", g_GuestState[idx].VmcsRegion);
        Log("[+] VMXON Region is allocated at ===============> %llx", g_GuestState[idx].VmxonRegion);
        Log("=====================================================");

        KeRevertToUserAffinityThreadEx(0);
    }

    return true;
}


VOID TerminateVMX()
{
    KAFFINITY AffinityMask = 0;
    INT ProcessCount = KeQueryActiveProcessorCount(NULL);
    for (int idx = 0; idx < ProcessCount; idx++)
    {
        AffinityMask = MathPower(2, idx);
        KeSetSystemAffinityThread(AffinityMask);

        Log("=====================================================");
        Log("[+] Current Thread is executing in %d th logical processor", idx);

        __vmx_off();
        MmFreeContiguousMemory(PhysicalToVirtualAddress(g_GuestState[idx].VmxonRegion));
        MmFreeContiguousMemory(PhysicalToVirtualAddress(g_GuestState[idx].VmcsRegion));

        KeRevertToUserAffinityThreadEx(0);
    }

    Log("[+] VMX Operation turned off successfully.");
}


VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    TerminateVMX();
}


extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    Log("[+] DriverEntry call");
    
    DriverObject->DriverUnload = DriverUnload;

    if (!InitVMX())
    {
        Log("[-] InitVMX fail...");
        return STATUS_UNSUCCESSFUL;
    }

    Log("[+] DriverEntry end");
    return STATUS_SUCCESS;
}