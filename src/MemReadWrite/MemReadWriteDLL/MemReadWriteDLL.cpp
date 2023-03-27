// MemReadWriteDLL.cpp : DLL을 위해 내보낸 함수를 정의합니다.
//
#include <iostream>
#include <memory>
#include "pch.h"
#include "framework.h"
#include "MemReadWriteDLL.h"
#include "utils.h"
#include "resource.h"
#include "../MemReadWriteCode.h"

#define DRIVER_NAME L"\\\\.\\MemReadWriteDriver"
#define SERVICE_NAME L"MemReadWriteDriver"
HMODULE g_module_handle = nullptr;


mem::BaseException::BaseException(const MemErrorCode error_code, const char* msg, int extra_error_code)
    : m_error_code(error_code)
    , m_last_error(GetLastError())
    , std::exception(msg)
    , m_extra_error_code(extra_error_code)
{
    sprintf_s(this->m_buf, sizeof(this->m_buf), "msg : ( %s ),  error_code : %d, last_error : %d, extra_error_code : %d"
                                                , std::exception::what()
                                                , this->m_error_code
                                                , this->m_last_error
                                                , this->m_extra_error_code);
}

const char* mem::BaseException::what() const
{
    return this->m_buf;
}

mem::DriverInstallException::DriverInstallException(const MemErrorCode error_code, const char* msg, int extra_error_code)
    : BaseException(error_code, msg, extra_error_code)
{
}


mem::DriverOpenException::DriverOpenException(const char* msg)
    : BaseException(MemErrorCode::DRIVER_OPEN_FAIL, msg)
{
}


mem::DriverIOException::DriverIOException(const char* msg)
    : BaseException(MemErrorCode::DRIVER_IO_FAIL, msg)
{
}


std::wstring temp_path(const std::wstring& driver_name)
{
    WCHAR buf[MAX_PATH] = { 0, };

    if (!GetTempPathW(MAX_PATH, buf))
        return std::wstring();

    return std::wstring(buf) + L"\\" + driver_name;
}


void mem::install_driver()
{
#ifdef _DEBUG
    int resource_id = IDR_DEBUG_MEM_DRIVER;
#else
    int resource_id = IDR_RELEASE_MEM_DRIVER;
#endif

    if (!g_module_handle)
        throw DriverInstallException(MemErrorCode::DLL_HANDLE_IS_NULL, "dll의 핸들이 비어 있습니다");


    std::wstring file_path = temp_path(L"MemReadWriteDriver.sys");
    bool result = resource_to_file(g_module_handle, resource_id, L"SYS", file_path);
    if (!result)
        throw DriverInstallException(MemErrorCode::FILE_SAVE_FAIL, "드라이버 파일을 저장하는데 실패했습니다");
    

    ServiceManager manager;
    try
    {
        manager.open_scm();
        manager.create_service(SERVICE_NAME, L"Memory Read Write Driver", file_path);
        manager.start();
    }
    catch (const ServiceBaseException& e)
    {
       throw DriverInstallException(MemErrorCode::DRIVER_INSTALL_FAIL, e.what(), (int)e.m_error_code);
    }
}

void mem::uninstall_driver()
{
    ServiceManager manager;
    try
    {
        manager.open_scm();
        manager.open_service(SERVICE_NAME);
        manager.stop();
        manager.delete_service();
    }
    catch (const ServiceBaseException& e)
    {
        throw DriverInstallException(MemErrorCode::DRIVER_UNINSTALL_FAIL, e.what(), (int)e.m_error_code);
    }
}


mem::DriverHelper::DriverHelper(ULONG pid)
    : m_pid(pid)
    , m_driver(nullptr)
{
    this->m_driver = CreateFileW(DRIVER_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (this->m_driver == INVALID_HANDLE_VALUE)
        throw DriverOpenException("드라이버를 열 수 없습니다");
}

mem::DriverHelper::~DriverHelper()
{
    if (this->m_driver)
    {
        CloseHandle(this->m_driver);
        this->m_driver = nullptr;
    }
}

ULONGLONG mem::DriverHelper::read_data(ULONGLONG address, ULONG size)
{
    READ_REQUEST info = { 0, };
    info.ProcessID = this->m_pid;
    info.Address = address;
    info.Size = size;

    bool result = DeviceIoControl(this->m_driver, IO_CTL_READ_REQUEST, &info, sizeof(info), &info, sizeof(info), NULL, NULL);
    if (!result)
        throw DriverIOException("데이터 읽기를 실패했습니다");

    return info.Response;
}

BYTE mem::DriverHelper::read_byte(ULONGLONG address)
{
    return (BYTE)this->read_data(address, sizeof(BYTE));
}

WORD mem::DriverHelper::read_word(ULONGLONG address)
{
    return (WORD)this->read_data(address, sizeof(WORD));
}

DWORD mem::DriverHelper::read_dword(ULONGLONG address)
{
    return (DWORD)this->read_data(address, sizeof(DWORD));
}

FLOAT mem::DriverHelper::read_float(ULONGLONG address)
{
    DWORD val = (DWORD)this->read_data(address, sizeof(DWORD));
    return *((FLOAT*)&val);
}

ULONGLONG mem::DriverHelper::read_ulonglong(ULONGLONG address)
{
    return this->read_data(address, sizeof(ULONGLONG));
}

void mem::DriverHelper::write_data(ULONGLONG address, ULONGLONG value, ULONG size)
{
    WRITE_REQUEST info = { 0, };
    info.ProcessID = this->m_pid;
    info.Address = address;
    info.Value = value;
    info.Size = size;

    bool result = DeviceIoControl(this->m_driver, IO_CTL_WRITE_REQUEST, &info, sizeof(info), NULL, 0, NULL, NULL);
    if (!result)
        throw DriverIOException("데이터 쓰기를 실패했습니다");
}


void mem::DriverHelper::write_byte(ULONGLONG address, BYTE value)
{
    this->write_data(address, value, sizeof(value));
}


void mem::DriverHelper::write_word(ULONGLONG address, WORD value)
{
    this->write_data(address, value, sizeof(value));
}

void mem::DriverHelper::write_dword(ULONGLONG address, DWORD value)
{
    this->write_data(address, value, sizeof(value));
}

void mem::DriverHelper::write_float(ULONGLONG address, FLOAT value)
{
    DWORD temp = *((DWORD*)&value);
    this->write_data(address, temp, sizeof(temp));
}

void mem::DriverHelper::write_ulonglong(ULONGLONG address, ULONGLONG value)
{
    this->write_data(address, value, sizeof(value));
}

int InstallDriver()
{
    try
    {
        mem::install_driver();
    }
    catch (const mem::BaseException& e)
    {
        return (int)e.m_error_code;
    }

    return 0;
}

int UninstallDriver()
{
    try
    {
        mem::uninstall_driver();
    }
    catch (const mem::BaseException& e)
    {
        return (int)e.m_error_code;
    }

    return 0;
}



thread_local std::unique_ptr<mem::DriverHelper> g_helper = nullptr;
bool Open(ULONG pid)
{
    try
    {
        g_helper = std::unique_ptr<mem::DriverHelper>(new mem::DriverHelper(pid));
    }
    catch (const mem::BaseException& e)
    {
        return false;
    }

    return true;
}

BYTE ReadByte(ULONGLONG address)
{
    if (!g_helper)
        return 0;

    return g_helper->read_byte(address);
}

WORD ReadWord(ULONGLONG address)
{
    if (!g_helper)
        return 0;

    return g_helper->read_word(address);
}

DWORD ReadDword(ULONGLONG address)
{
    if (!g_helper)
        return 0;

    return g_helper->read_dword(address);
}

FLOAT ReadFloat(ULONGLONG address)
{
    if (!g_helper)
        return 0;

    return g_helper->read_float(address);
}

ULONGLONG ReadUlonglong(ULONGLONG address)
{
    if (!g_helper)
        return 0;

    return g_helper->read_ulonglong(address);
}
