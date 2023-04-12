#pragma once
#include <wdm.h>


#define log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[SSDTIndex]" format "\n", ##__VA_ARGS__)