#include <ntddk.h>
#include <wdm.h>


#define log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[String]" "[" __FUNCTION__ "]" format "\n", __VA_ARGS__)


void init_const_string()
{
    UNICODE_STRING const_string1 = RTL_CONSTANT_STRING(L"Hello, World!");
    log("const_string1: %wZ", &const_string1);

    UNICODE_STRING const_string2 = { 0, };
    RtlInitUnicodeString(&const_string2, L"Hello, World!");
    log("const_string2: %wZ", &const_string2);
}


void init_dynamic_string()
{
    UNICODE_STRING const_string = RTL_CONSTANT_STRING(L"Hello, World!");
    USHORT size = const_string.MaximumLength;

    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'irts');
    if (buffer == nullptr)
    {
        log("ExAllocatePool2 failed");
        return;
    }

    RtlZeroMemory(buffer, size);
    UNICODE_STRING dynamic_string1 = { 0, };
    dynamic_string1.MaximumLength = size;
    dynamic_string1.Buffer = (PWCH)buffer;

    RtlCopyUnicodeString(&dynamic_string1, &const_string);
    log("dynamic_string1: %wZ", &dynamic_string1);

    ExFreePool(buffer);
}


void compare_string1()
{
    UNICODE_STRING upper_string1 = RTL_CONSTANT_STRING(L"HELLO, WORLD!");
    UNICODE_STRING lower_string1 = RTL_CONSTANT_STRING(L"hello, world!");

    bool is_case_sensitive = TRUE; // TRUE or FALSE, case sensitive or insensitive
    BOOLEAN equal = RtlEqualUnicodeString(&upper_string1, &lower_string1, is_case_sensitive);
    if (equal)
        log("upper_string1 and lower_string1 are equal");

    else
        log("upper_string1 and lower_string1 are not equal");
}


void compare_string2()
{
    UNICODE_STRING upper_string1 = RTL_CONSTANT_STRING(L"HELLO, WORLD!");
    UNICODE_STRING lower_string1 = RTL_CONSTANT_STRING(L"hello, world!");
    bool is_case_sensitive = TRUE; // TRUE or FALSE, case sensitive or insensitive
    LONG result = RtlCompareUnicodeString(&upper_string1, &lower_string1, is_case_sensitive);
    if (result == 0)
        log("upper_string1 and lower_string1 are equal");

    else if (result > 0)
        log("upper_string1 is greater than lower_string1");

    else
        log("upper_string1 is less than lower_string1");
}


void prefix_compare_string()
{
    UNICODE_STRING prefix_string = RTL_CONSTANT_STRING(L"Hello, World!");
    UNICODE_STRING target_string1 = RTL_CONSTANT_STRING(L"Hello, World! Prefix String1");
    UNICODE_STRING target_string2 = RTL_CONSTANT_STRING(L"Prefix String2");
    bool is_case_sensitive = TRUE; // TRUE or FALSE, case sensitive or insensitive
    BOOLEAN is_prefix = RtlPrefixUnicodeString(&prefix_string, &target_string1, is_case_sensitive);
    if (is_prefix)
        log("target_string1 is prefix of string");

    else
        log("target_string1 is not prefix of string");


    is_prefix = RtlPrefixUnicodeString(&prefix_string, &target_string2, is_case_sensitive);
    if (is_prefix)
        log("target_string2 is prefix of string");
    else
        log("target_string2 is not prefix of string");
}


void contains_string()
{
    UNICODE_STRING contains_string = RTL_CONSTANT_STRING(L"World!");
    UNICODE_STRING target_string1 = RTL_CONSTANT_STRING(L"Hello, World! Contains String");
    UNICODE_STRING target_string2 = RTL_CONSTANT_STRING(L"Hello, Contains String");

    auto is_contains = [](PUNICODE_STRING src, PUNICODE_STRING contains) -> bool
    {
        if (src->Length < contains->Length)
            return false;

        USHORT max_idx = src->Length - contains->Length;
        for (USHORT idx = 0; idx < max_idx; idx++)
        {
            if (RtlEqualMemory(src->Buffer + idx, contains->Buffer, contains->Length))
                return true;
        }

        return false;
    };

    bool result = is_contains(&target_string1, &contains_string);
    if (result)
        log("target_string1 contains contains_string");

    else
        log("target_string1 does not contain contains_string");


    result = is_contains(&target_string2, &contains_string);
    if (result)
        log("target_string2 contains contains_string");

    else
        log("target_string2 does not contain contains_string");
}



void DriverUnload(PDRIVER_OBJECT driver_object)
{
    UNREFERENCED_PARAMETER(driver_object);
    log("DriverUnload");
}


extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
    UNREFERENCED_PARAMETER(registry_path);
    log("Driver loaded");
    driver_object->DriverUnload = DriverUnload;

    init_const_string();
    init_dynamic_string();
    compare_string1();
    compare_string2();
    prefix_compare_string();
    contains_string();
    log("DriverEntry finished");
    return STATUS_SUCCESS;
}