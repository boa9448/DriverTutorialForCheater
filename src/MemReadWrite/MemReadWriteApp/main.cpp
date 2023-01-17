#ifdef _DEBUG
#pragma comment(lib, "..\\..\\..\\x64\\Debug\\MemReadWriteDLL.lib")
#else
#pragma comment(lib, "..\\..\\..\\x64\\Release\\MemReadWriteDLL.lib")
#endif

#include <iostream>
#include "..\MemReadWriteDLL\MemReadWriteDLL.h"

int main()
{
    setlocale(LC_ALL, "");
    try
    {
        mem::install_driver();


        ULONG cur_pid = GetCurrentProcessId();
        HMODULE mod_handle = GetModuleHandle(NULL);
        ULONGLONG sig = 'ZM';

        mem::DriverHelper driver(cur_pid);
        auto val = driver.read_data((ULONGLONG)mod_handle, 2);
        std::cout << "val is " << val << std::endl;

        if (sig == val)
            std::cout << "sig match" << std::endl;
        else
            std::cout << "sig miss match" << std::endl;

        std::cout << "press enter";
        std::cin.get();

        mem::uninstall_driver();
    }
    catch (const mem::BaseException& e)
    {
        std::cout << e.what() << std::endl;
    }

    return 0;
}