#ifdef IS_DRIVER
#include <ntddk.h>
#else
#include <windows.h>
#endif


#define IO_CTL_READ_REQUEST         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0701, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_CTL_WRITE_REQUEST        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0702, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _ReadRequest
{
    ULONG ProcessID;

    ULONGLONG Address;
    ULONGLONG Response;
    ULONG Size;
} READ_REQUEST, * PREAD_REQUEST;

typedef struct _WriteRequest
{
    ULONG ProcessID;

    ULONGLONG Address;
    ULONGLONG Value;
    ULONG Size;
} WRITE_REQUEST, * PWRITE_REQUEST;