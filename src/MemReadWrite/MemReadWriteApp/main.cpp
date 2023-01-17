#ifdef _DEBUG
#pragma comment(lib, "..\\..\\..\\x64\\Debug\\MemReadWriteDLL.lib")
#else
#pragma comment(lib, "..\\..\\..\\x64\\Release\\MemReadWriteDLL.lib")
#endif

#include <iostream>
#include <vector>
#include "..\MemReadWriteDLL\MemReadWriteDLL.h"

int main()
{
    setlocale(LC_ALL, "");
    try
    {
        mem::install_driver();


        ULONG cur_pid = GetCurrentProcessId();
        HMODULE mod_handle = GetModuleHandle(NULL);
        std::vector<float> num_list = { 0.1f, 0.2f, 0.3f, 0.4f };
        mem::DriverHelper driver(cur_pid);

        ULONGLONG address = (ULONGLONG)num_list.data();

        auto val = driver.read_float(address);
        std::cout << "val is " << val << std::endl;
        for (const auto num : num_list)
            std::cout << num << " ";
        std::cout << std::endl;

        address += 4;
        driver.write_float(address, 0.9f);
        val = driver.read_float(address);
        std::cout << "new val is " << val << std::endl;

        for (const auto num : num_list)
            std::cout << num << " ";
        std::cout << std::endl;

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