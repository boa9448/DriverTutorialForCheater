#include <ntddk.h>
#include <wdm.h>


#define Log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[KernelThread]" format "\n", ##__VA_ARGS__)


//https://github.com/vRare/AutoSpitta-x64/blob/5f5a3c5306f0606190c10a9b3743278c6b14932c/hacks.c#L9
NTSTATUS Sleep(ULONGLONG milliseconds)
{
	LARGE_INTEGER delay;
	ULONG* split;

	milliseconds *= 1000000;

	milliseconds /= 100;

	milliseconds = ~milliseconds + 1;

	split = (ULONG*)&milliseconds;

	delay.LowPart = *split;

	split++;

	delay.HighPart = *split;


	KeDelayExecutionThread(KernelMode, 0, &delay);

	return STATUS_SUCCESS;
}


void ThreadProc(PVOID Param)
{
	UNREFERENCED_PARAMETER(Param);

    Log("Thread start!");
	for (int idx = 0; idx < 10; idx++)
	{
		Log("Thread run... %d", idx);
		Sleep(1000);
	}

	Log("Thread end!");
	PsTerminateSystemThread(0);
}


void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
}


extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    Log("DriverEntry call");

    DriverObject->DriverUnload = DriverUnload;

    HANDLE ThreadHandle = NULL;
	NTSTATUS Status = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, ThreadProc, NULL);
	if (!NT_SUCCESS(Status))
	{
		Log("PsCreateSystemThread fail... 0x%x", Status);
		return STATUS_UNSUCCESSFUL;
	}

    Log("DriverEntry end");
    return STATUS_SUCCESS;
}