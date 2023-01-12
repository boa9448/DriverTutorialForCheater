#include <iostream>
#include <Windows.h>

#include "../communication_header.h"

int main()
{
    HANDLE driver_handle = CreateFileW(L"\\\\.\\CommunicationDriver"
                                    , GENERIC_READ | GENERIC_WRITE
                                    , 0
                                    , NULL
                                    , OPEN_EXISTING
                                    , 0
                                    , NULL);

    if (driver_handle == INVALID_HANDLE_VALUE)
    {
        std::cout << "CreateFile Fail... " << GetLastError() << std::endl;
        return 0;
    }

    CommunicationInfo info = { 1, 2, 3 };
    DWORD write_size = 0;
    BOOL result = WriteFile(driver_handle, &info, sizeof(info), &write_size, NULL);
    if (!result)
    {
        std::cout << "WriteFile Fail... " << GetLastError() << std::endl;
        CloseHandle(driver_handle);
        return 0;
    }

    std::cout << "write size : " << write_size << std::endl;

    DWORD read_size = 0;
    ZeroMemory(&info, sizeof(info));
    result = ReadFile(driver_handle, &info, sizeof(info), &read_size, NULL);
    if (!result)
    {
        std::cout << "ReadFile fail... " << GetLastError() << std::endl;
        CloseHandle(driver_handle);
        return 0;
    }

    std::cout << "read size : " << read_size << std::endl;
    char buf[255] = { 0, };
    sprintf_s(buf, sizeof(buf), "x : %d, y : %d, z : %d", info.x, info.y, info.z);
    std::cout << buf << std::endl;

    CloseHandle(driver_handle);
    return 0;
}