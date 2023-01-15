#include <ntddk.h>
#include <wdm.h>

#include "undocumented.h"


#define Log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ProcessEnum]" format "\n", ##__VA_ARGS__)


NTQUERYSYSTEMINFORMATION NTQIS = NULL;
ZWQUERYSYSTEMINFORMATION ZWQIS = NULL;



void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    Log("[+] DriverUnload call");
}


NTSTATUS EnumProcess()
{
    ULONG Size = 0;
    NTSTATUS Status = NTQIS(SystemProcessInformation, NULL, 0, &Size);
    if (Status != STATUS_INFO_LENGTH_MISMATCH)
    {
        Log("[-] not STATUS_INFO_LENGTH_MISMATCH ... %u", Status);
        return Status;
    }

    PSYSTEM_PROCESS_INFORMATION Buffer = (PSYSTEM_PROCESS_INFORMATION)
                                            ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)Size * 2, 'munE');

    if (!Buffer)
    {
        Log("[-] STATUS_NO_MEMORY ...");
        return STATUS_NO_MEMORY;
    }

    Status = NTQIS(SystemProcessInformation, Buffer, Size * 2, NULL);
    if (!NT_SUCCESS(Status))
    {
        Log("[-] QuerySystemInformation Fail ... %u", Status);
        ExFreePoolWithTag(Buffer, 'munE');
        return Status;
    }

    PSYSTEM_PROCESS_INFORMATION Entry = Buffer;

    while (true)
    {
        if (Entry->ImageName.Buffer != NULL)
            Log("[+] %.*ws %llu", (unsigned int)(Entry->ImageName.Length / sizeof(WCHAR)), Entry->ImageName.Buffer
                                , (ULONGLONG)Entry->UniqueProcessId);

        if (Entry->NextEntryOffset == 0)
            break;

        Entry = (PSYSTEM_PROCESS_INFORMATION)((UINT_PTR)Entry + Entry->NextEntryOffset);
    }

    ExFreePoolWithTag(Buffer, 'munE');
    return STATUS_SUCCESS;
}


extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    Log("[+] DriverEntry call");
    DriverObject->DriverUnload = DriverUnload;


    UNICODE_STRING RoutineName;
    RtlInitUnicodeString(&RoutineName, L"ZwQuerySystemInformation");
    ZWQIS = (ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&RoutineName);
    if (!ZWQIS)
    {
        Log("[-] Get ZwQuerySystemInformation Address Fail...");
        return STATUS_UNSUCCESSFUL;
    }

    RtlInitUnicodeString(&RoutineName, L"NtQuerySystemInformation");
    NTQIS = (NTQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&RoutineName);
    if (!NTQIS)
    {
        Log("[-] Get ZwQuerySystemInformation Address Fail...");
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS Status = EnumProcess();
    return Status;
}