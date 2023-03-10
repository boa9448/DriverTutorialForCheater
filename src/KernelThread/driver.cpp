#include <ntddk.h>
#include <wdm.h>


#define Log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[KernelThread]" format "\n", ##__VA_ARGS__)


NTSTATUS Sleep(ULONGLONG milliseconds)
{
    LARGE_INTEGER delay;

    milliseconds *= 1000000;
    milliseconds /= 100;
    milliseconds = ~milliseconds + 1;
    delay.QuadPart = milliseconds;

    KeDelayExecutionThread(KernelMode, 0, &delay);

    return STATUS_SUCCESS;
}


void ThreadProc(PVOID Param)
{
    UNREFERENCED_PARAMETER(Param);

    Log("[+] Thread start!");
    for (int idx = 0; idx < 10; idx++)
    {
        Log("[+] Thread run... %d", idx);
        Sleep(1000);
    }

    Log("[+] Thread end!");
    PsTerminateSystemThread(0);
}


void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
}


extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    Log("[+] DriverEntry call");

    DriverObject->DriverUnload = DriverUnload;

    HANDLE ThreadHandle = NULL;
    OBJECT_ATTRIBUTES Attr = { 0, };

    InitializeObjectAttributes(&Attr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    NTSTATUS Status = PsCreateSystemThread(&ThreadHandle
                                            , THREAD_ALL_ACCESS
                                            , &Attr
                                            , NULL
                                            , NULL
                                            , ThreadProc
                                            , NULL);
    if (!NT_SUCCESS(Status))
    {
        Log("[-] PsCreateSystemThread fail... 0x%x", Status);
        return STATUS_UNSUCCESSFUL;
    }

    ZwClose(ThreadHandle);
    Log("[+] DriverEntry end");
    return STATUS_SUCCESS;
}