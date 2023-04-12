#include <ntifs.h>

#include "global.hpp"
#include "ssdt_index.hpp"
#include "ssdt.hpp"

namespace ssdt
{
    typedef struct _SSDTStruct
    {
        LONG* service_table;
        PVOID counter_table;
        ULONGLONG number_of_service;
        PCHAR argument_table;
    }SSDTStruct, *PSSDTStruct;

    extern "C"
        NTKERNELAPI
        PIMAGE_NT_HEADERS
        NTAPI
        RtlImageNtHeader(
            _In_ PVOID Base);

    typedef enum _SYSTEM_INFORMATION_CLASS
    {
        SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
        SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
        SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
        SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
        SystemPathInformation, // not implemented
        SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
        SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
        SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
        SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
        SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
        SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
        SystemModuleInformation, // q: RTL_PROCESS_MODULES
        SystemLocksInformation, // q: RTL_PROCESS_LOCKS
        SystemStackTraceInformation, // q: RTL_PROCESS_BACKTRACES
        SystemPagedPoolInformation, // not implemented
        SystemNonPagedPoolInformation, // not implemented
        SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
        SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
        SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
        SystemVdmInstemulInformation, // q
        SystemVdmBopInformation, // not implemented // 20
        SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
        SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
        SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION
        SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
        SystemFullMemoryInformation, // not implemented
        SystemLoadGdiDriverInformation, // s (kernel-mode only)
        SystemUnloadGdiDriverInformation, // s (kernel-mode only)
        SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
        SystemSummaryMemoryInformation, // not implemented
        SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
        SystemPerformanceTraceInformation, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
        SystemObsolete0, // not implemented
        SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
        SystemCrashDumpStateInformation, // s (requires SeDebugPrivilege)
        SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
        SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
        SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
        SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
        SystemPrioritySeperation, // s (requires SeTcbPrivilege)
        SystemVerifierAddDriverInformation, // s (requires SeDebugPrivilege) // 40
        SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
        SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION
        SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
        SystemCurrentTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION
        SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
        SystemTimeSlipNotification, // s (requires SeSystemtimePrivilege)
        SystemSessionCreate, // not implemented
        SystemSessionDetach, // not implemented
        SystemSessionInformation, // not implemented (SYSTEM_SESSION_INFORMATION)
        SystemRangeStartInformation, // q: SYSTEM_RANGE_START_INFORMATION // 50
        SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
        SystemVerifierThunkExtend, // s (kernel-mode only)
        SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
        SystemLoadGdiDriverInSystemSpace, // s (kernel-mode only) (same as SystemLoadGdiDriverInformation)
        SystemNumaProcessorMap, // q
        SystemPrefetcherInformation, // q: PREFETCHER_INFORMATION; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
        SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
        SystemRecommendedSharedDataAlignment, // q
        SystemComPlusPackage, // q; s
        SystemNumaAvailableMemory, // 60
        SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION
        SystemEmulationBasicInformation, // q
        SystemEmulationProcessorInformation,
        SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
        SystemLostDelayedWriteInformation, // q: ULONG
        SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
        SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
        SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
        SystemHotpatchInformation, // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
        SystemObjectSecurityMode, // q: ULONG // 70
        SystemWatchdogTimerHandler, // s (kernel-mode only)
        SystemWatchdogTimerInformation, // q (kernel-mode only); s (kernel-mode only)
        SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION
        SystemWow64SharedInformationObsolete, // not implemented
        SystemRegisterFirmwareTableInformationHandler, // s (kernel-mode only)
        SystemFirmwareTableInformation, // SYSTEM_FIRMWARE_TABLE_INFORMATION
        SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
        SystemVerifierTriageInformation, // not implemented
        SystemSuperfetchInformation, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
        SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
        SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
        SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
        SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[]
        SystemVerifierCancellationInformation, // not implemented // name:wow64:whNT32QuerySystemVerifierCancellationInformation
        SystemProcessorPowerInformationEx, // not implemented
        SystemRefTraceInformation, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
        SystemSpecialPoolInformation, // q; s (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
        SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
        SystemErrorPortInformation, // s (requires SeTcbPrivilege)
        SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
        SystemHypervisorInformation, // q; s (kernel-mode only)
        SystemVerifierInformationEx, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
        SystemTimeZoneInformation, // s (requires SeTimeZonePrivilege)
        SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
        SystemCoverageInformation, // q; s // name:wow64:whNT32QuerySystemCoverageInformation; ExpCovQueryInformation
        SystemPrefetchPatchInformation, // not implemented
        SystemVerifierFaultsInformation, // s (requires SeDebugPrivilege)
        SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
        SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
        SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION // 100
        SystemNumaProximityNodeInformation, // q
        SystemDynamicTimeZoneInformation, // q; s (requires SeTimeZonePrivilege)
        SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
        SystemProcessorMicrocodeUpdateInformation, // s
        SystemProcessorBrandString, // q // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
        SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
        SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // since WIN7 // KeQueryLogicalProcessorRelationship
        SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[]
        SystemStoreInformation, // q; s // SmQueryStoreInformation
        SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
        SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
        SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
        SystemCpuQuotaInformation, // q; s // PsQueryCpuQuotaInformation
        SystemNativeBasicInformation, // not implemented
        SystemSpare1, // not implemented
        SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
        SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
        SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
        SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
        SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
        SystemNodeDistanceInformation, // q
        SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
        SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
        SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
        SystemSessionBigPoolInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
        SystemBootGraphicsInformation, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
        SystemScrubPhysicalMemoryInformation, // q; s: MEMORY_SCRUB_INFORMATION
        SystemBadPageInformation,
        SystemProcessorProfileControlArea, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
        SystemCombinePhysicalMemoryInformation, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
        SystemEntropyInterruptTimingCallback,
        SystemConsoleInformation, // q: SYSTEM_CONSOLE_INFORMATION
        SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION
        SystemThrottleNotificationInformation,
        SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
        SystemDeviceDataInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
        SystemDeviceDataEnumerationInformation,
        SystemMemoryTopologyInformation, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
        SystemMemoryChannelInformation, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
        SystemBootLogoInformation, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
        SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // since WINBLUE
        SystemSpare0,
        SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
        SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
        SystemSecureBootInformation, // q: SYSTEM_SECUREBOOT_INFORMATION
        SystemEntropyInterruptTimingRawInformation,
        SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
        SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
        SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
        SystemBootMetadataInformation, // 150
        SystemSoftRebootInformation,
        SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
        SystemOfflineDumpConfigInformation,
        SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
        SystemRegistryReconciliationInformation,
        SystemEdidInformation,
        SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
        SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
        SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
        SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION // 160
        SystemVmGenerationCountInformation,
        SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
        SystemKernelDebuggerFlags,
        SystemCodeIntegrityPolicyInformation, // q: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
        SystemIsolatedUserModeInformation, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
        SystemHardwareSecurityTestInterfaceResultsInformation,
        SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
        SystemAllowedCpuSetsInformation,
        SystemDmaProtectionInformation, // q: SYSTEM_DMA_PROTECTION_INFORMATION
        SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
        SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
        SystemCodeIntegrityPolicyFullInformation,
        SystemAffinitizedInterruptProcessorInformation,
        SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
        SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
        SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
        SystemWin32WerStartCallout,
        SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
        SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
        SystemInterruptSteeringInformation, // 180
        SystemSupportedProcessorArchitectures,
        SystemMemoryUsageInformation, // q: SYSTEM_MEMORY_USAGE_INFORMATION
        SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
        SystemPhysicalMemoryInformation, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
        SystemControlFlowTransition,
        SystemKernelDebuggingAllowed,
        SystemActivityModerationExeState, // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
        SystemActivityModerationUserSettings, // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
        SystemCodeIntegrityPoliciesFullInformation,
        SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
        SystemIntegrityQuotaInformation,
        SystemFlushInformation, // q: SYSTEM_FLUSH_INFORMATION
        SystemProcessorIdleMaskInformation, // since REDSTONE3
        SystemSecureDumpEncryptionInformation,
        SystemWriteConstraintInformation, // SYSTEM_WRITE_CONSTRAINT_INFORMATION
        MaxSystemInfoClass
    } SYSTEM_INFORMATION_CLASS;


    typedef struct _SYSTEM_THREAD_INFORMATION
    {
        LARGE_INTEGER KernelTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER CreateTime;
        ULONG WaitTime;
        PVOID StartAddress;
        CLIENT_ID ClientId;
        KPRIORITY Priority;
        LONG BasePriority;
        ULONG ContextSwitches;
        ULONG ThreadState;
        KWAIT_REASON WaitReason;
    } SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;


    typedef struct _SYSTEM_PROCESS_INFORMATION
    {
        ULONG NextEntryOffset;
        ULONG NumberOfThreads;
        LARGE_INTEGER WorkingSetPrivateSize;
        ULONG HardFaultCount;
        ULONG NumberOfThreadsHighWatermark;
        ULONGLONG CycleTime;
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER KernelTime;
        UNICODE_STRING ImageName;
        KPRIORITY BasePriority;
        HANDLE UniqueProcessId;
        HANDLE InheritedFromUniqueProcessId;
        ULONG HandleCount;
        ULONG SessionId;
        ULONG_PTR UniqueProcessKey;
        SIZE_T PeakVirtualSize;
        SIZE_T VirtualSize;
        ULONG PageFaultCount;
        SIZE_T PeakWorkingSetSize;
        SIZE_T WorkingSetSize;
        SIZE_T QuotaPeakPagedPoolUsage;
        SIZE_T QuotaPagedPoolUsage;
        SIZE_T QuotaPeakNonPagedPoolUsage;
        SIZE_T QuotaNonPagedPoolUsage;
        SIZE_T PagefileUsage;
        SIZE_T PeakPagefileUsage;
        SIZE_T PrivatePageCount;
        LARGE_INTEGER ReadOperationCount;
        LARGE_INTEGER WriteOperationCount;
        LARGE_INTEGER OtherOperationCount;
        LARGE_INTEGER ReadTransferCount;
        LARGE_INTEGER WriteTransferCount;
        LARGE_INTEGER OtherTransferCount;
        SYSTEM_THREAD_INFORMATION Threads[1]; // SystemProcessInformation
        // SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1]; // SystemExtendedProcessinformation
        // SYSTEM_EXTENDED_THREAD_INFORMATION + SYSTEM_PROCESS_INFORMATION_EXTENSION // SystemFullProcessInformation
    } SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


    typedef NTSTATUS(NTAPI* ZWQUERYSYSTEMINFORMATION)(
        IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
        OUT PVOID SystemInformation,
        IN ULONG SystemInformationLength,
        OUT PULONG ReturnLength OPTIONAL);


    PSSDTStruct g_ssdt_table = nullptr;
    PSSDTStruct g_ssdt_shadow_table = nullptr;

    KAPC_STATE g_old_apc_state;


    //Based on: http://alter.org.ua/docs/nt_kernel/procaddr
    PVOID get_kernel_base(PULONG image_size)
    {
        typedef struct _SYSTEM_MODULE_ENTRY
        {
            HANDLE Section;
            PVOID MappedBase;
            PVOID ImageBase;
            ULONG ImageSize;
            ULONG Flags;
            USHORT LoadOrderIndex;
            USHORT InitOrderIndex;
            USHORT LoadCount;
            USHORT OffsetToFileName;
            UCHAR FullPathName[256];
        } SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

#pragma warning(disable:4200)
        typedef struct _SYSTEM_MODULE_INFORMATION
        {
            ULONG Count;
            SYSTEM_MODULE_ENTRY Module[0];
        } SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

        PVOID module_base = nullptr;

        UNICODE_STRING routine_name = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");
        ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&routine_name);

        ULONG info_buffer_size = 0;
        NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation
            , nullptr
            , 0
            , &info_buffer_size);

        if (!info_buffer_size)
        {
            log("[-] ssdt::get_kernel_base ZwQuerySystemInformation (1) failed...");
            return NULL;
        }

        PSYSTEM_MODULE_INFORMATION info_buffer = nullptr;
        info_buffer = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, info_buffer_size * 2, 'smaH');
        if (!info_buffer)
        {
            log("[-] ssdt::get_kernel_base ExAllocatePool failed...");
            return NULL;
        }

        memset(info_buffer, 0, info_buffer_size * 2);

        status = ZwQuerySystemInformation(SystemModuleInformation,
            info_buffer,
            info_buffer_size * 2,
            &info_buffer_size);

        if (NT_SUCCESS(status))
        {
            module_base = info_buffer->Module[0].ImageBase;
            if (image_size)
                *image_size = info_buffer->Module[0].ImageSize;
        }
        else
            log("[-] ssdt::get_kernel_base ZwQuerySystemInformation (2) failed...");

        ExFreePool(info_buffer);

        return module_base;
    }


    ULONG get_process_id_from_name(PUNICODE_STRING process_name)
    {
        UNICODE_STRING routine_name = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");
        ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&routine_name);

        ULONG size;
        NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, nullptr, 0, &size);
        if (status != STATUS_INFO_LENGTH_MISMATCH)
        {
            log("[-] ssdt::get_process_id_from_name ZwQuerySystemInformation failed... (1)");
            return 0;
        }

        PSYSTEM_PROCESS_INFORMATION process_info = nullptr;
        process_info = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, 2 * size, 'smaH');

        if (process_info == nullptr)
        {
            log("[-] ssdt::get_process_id_from_name ExAllocatePool failed...");
            return 0;
        }

        status = ZwQuerySystemInformation(SystemProcessInformation, process_info, size * 2, &size);
        if (!NT_SUCCESS(status))
        {
            log("[-] ssdt::get_process_id_from_name ZwQuerySystemInformation failed... (2)");
            ExFreePool(process_info);
            return 0;
        }

        PSYSTEM_PROCESS_INFORMATION entry = process_info;
        ULONG pid = 0;

        while (true)
        {
            if (RtlCompareUnicodeString(&entry->ImageName, process_name, false) == 0)
            {
                pid = (ULONG)(ULONG_PTR)entry->UniqueProcessId;
                break;
            }

            if (entry->NextEntryOffset == 0)
                break;

            entry = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)entry + entry->NextEntryOffset);
        }

        ExFreePool(process_info);
        return pid;
    }


    bool attach_winlogon()
    {
        __try
        {
            UNICODE_STRING process_name;
            RtlInitUnicodeString(&process_name, L"winlogon.exe");
            ULONG pid = get_process_id_from_name(&process_name);
            if (pid == 0)
            {
                log("[-] ssdt::attach_winlogon Failed to get winlogon pid");
                return false;
            }

            PEPROCESS eprocess;
            NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &eprocess);
            if (!NT_SUCCESS(status))
            {
                log("[-] ssdt::attach_winlogon PsLookupProcessByProcessId failed...");
                return false;
            }

            KeStackAttachProcess(eprocess, &g_old_apc_state);
            ObDereferenceObject(eprocess);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            log("[-] ssdt::attach_winlogon Exception occurred...");
        }

        log("[+] ssdt::attach_winlogon Attached to winlogon");
        return true;
    }


    void detach_winlogon()
    {
        KeUnstackDetachProcess(&g_old_apc_state);
        log("[+] ssdt::detach_winlogon Detached from winlogon");
    }

    bool find_ssdt()
    {
        ULONG kernel_size;
        ULONG_PTR kernel_base = (ULONG_PTR)get_kernel_base(&kernel_size);
        if (kernel_base == 0 || kernel_size == 0)
        {
            log("[-] ssdt::init Failed to get kernel base");
            return false;
        }

        // Find .text section
        PIMAGE_NT_HEADERS nt_header = RtlImageNtHeader((PVOID)kernel_base);
        PIMAGE_SECTION_HEADER text_section = nullptr;
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_header);
        for (ULONG i = 0; i < nt_header->FileHeader.NumberOfSections; ++i)
        {
            char section_name[IMAGE_SIZEOF_SHORT_NAME + 1];
            RtlCopyMemory(section_name, section->Name, IMAGE_SIZEOF_SHORT_NAME);
            section_name[IMAGE_SIZEOF_SHORT_NAME] = '\0';
            if (strncmp(section_name, ".text", sizeof(".text") - sizeof(char)) == 0)
            {
                text_section = section;
                break;
            }
            section++;
        }
        if (text_section == nullptr)
        {
            log("[-] ssdt::init Failed to find .text section");
            return false;
        }

        // Find KiSystemServiceStart in .text
        // KiSystemServiceStartPattern
        const unsigned char pattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };

        const ULONG signature_size = sizeof(pattern);
        bool found = false;
        ULONG offset;
        for (offset = 0; offset < text_section->Misc.VirtualSize - signature_size; offset++)
        {
            if (RtlCompareMemory(((unsigned char*)kernel_base + text_section->VirtualAddress + offset), pattern, signature_size) == signature_size)
            {
                found = true;
                break;
            }
        }
        if (!found)
        {
            log("[-] ssdt::init Failed to find KiSystemServiceStart");
            return false;
        }

        // lea r10, KeServiceDescriptorTable
        // lea r11, KeServiceDescriptorTableShadow
        ULONG_PTR address = kernel_base + text_section->VirtualAddress + offset + signature_size + 7;
        LONG relative_offset = 0;
        if ((*(unsigned char*)address == 0x4c) &&
            (*(unsigned char*)(address + 1) == 0x8d) &&
            (*(unsigned char*)(address + 2) == 0x1d))
        {
            relative_offset = *(LONG*)(address + 3);
        }
        if (relative_offset == 0)
        {
            log("[-] ssdt::init Failed to find KeServiceDescriptorTable");
            return false;
        }

        g_ssdt_table = (SSDTStruct*)(address + relative_offset + 7);
        g_ssdt_shadow_table = (SSDTStruct*)(address + relative_offset + 7 + 0x20);

        log("[+] ssdt::init SSDT table: 0x%p", g_ssdt_table);
        log("[+] ssdt::init SSDT shadow table: 0x%p", g_ssdt_shadow_table);
        return true;
    }


    PVOID get_ssdt_function_addr(LPCSTR func_name)
    {
        if (g_ssdt_table == nullptr)
        {
            log("[-] ssdt::get_ssdt_function_addr SSDT table is not initialized");
            return nullptr;
        }

        int idx = ssdt_index::get_export_ssdt_index(func_name);
        if (idx == ssdt_index::SSDT_INDEX_ERROR)
        {
            log("[-] ssdt::get_ssdt_function_addr Failed to get ssdt index for %s", func_name);
            return nullptr;
        }

        if (idx >= g_ssdt_table->number_of_service)
        {
            log("[-] ssdt::get_ssdt_function_addr Invalid ssdt index for %s", func_name);
            return nullptr;
        }

        UINT_PTR ssdt_base = (UINT_PTR)g_ssdt_table->service_table;
        PVOID func_addr = (PVOID)((g_ssdt_table->service_table[idx] >> 4) + ssdt_base);
        log("[+] ssdt::get_ssdt_function_addr %s, address: 0x%p", func_name, func_addr);
        return func_addr;
    }

    PVOID get_ssdt_shadow_function_addr(LPCSTR func_name)
    {
        if (g_ssdt_shadow_table == nullptr)
        {
            log("[-] ssdt::get_ssdt_shadow_function_addr SSDT shadow table is not initialized");
            return nullptr;
        }

        int idx = ssdt_index::get_export_ssdt_shadow_index(func_name);
        if (idx == ssdt_index::SSDT_INDEX_ERROR)
        {
            log("[-] ssdt::get_ssdt_shadow_function_addr Failed to get ssdt shadow index for %s", func_name);
            return nullptr;
        }

        if (idx >= g_ssdt_shadow_table->number_of_service)
        {
            log("[-] ssdt::get_ssdt_shadow_function_addr Invalid ssdt shadow index for %s", func_name);
            return nullptr;
        }

        UINT_PTR ssdt_shadow_base = (UINT_PTR)g_ssdt_shadow_table->service_table;
        PVOID func_addr = (PVOID)((g_ssdt_shadow_table->service_table[idx] >> 4) + ssdt_shadow_base);
        log("[+] ssdt::get_ssdt_shadow_function_addr %s, address: 0x%p", func_name, func_addr);
        return func_addr;
    }

    bool init()
    {
        bool is_success = false;

        if (!attach_winlogon())
            return false;

        is_success = find_ssdt();
        detach_winlogon();

        return is_success;
    }

}