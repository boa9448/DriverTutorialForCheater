#pragma once
#include <string>
#include <format>
#include <exception>
#include <windows.h>


bool resource_to_file(HMODULE module_handle, int resoruce_id, const std::wstring& resoruce_type, const std::wstring& file_path)
{
	HRSRC hrsrc = FindResourceW(module_handle, MAKEINTRESOURCE(resoruce_id), resoruce_type.c_str());
	if (hrsrc == NULL) return FALSE;

	HANDLE hres = LoadResource(module_handle, hrsrc);
	if (hres == NULL) return FALSE;

	BYTE* resoruce = (BYTE*)LockResource(hres);
	if (resoruce == NULL) return FALSE;

	HANDLE hfile = CreateFileW(file_path.c_str(), GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hfile == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hfile);
		return FALSE;
	}

	DWORD file_size = SizeofResource(module_handle, hrsrc);
	DWORD write_size = 0;
	if (!WriteFile(hfile, resoruce, file_size, &write_size, NULL))
	{
		CloseHandle(hfile);
		return FALSE;
	}

	CloseHandle(hfile);
	return TRUE;
}


enum class ServiceErrorCode
{
    NONE
    , SCM_OPEN_FAIL
    , SERVICE_OPEN_FAIL
    , SERVICE_CREATE_FAIL
    , SERVICE_DELETE_FAIL
    , SERVICE_START_FAIL
    , SERVICE_STOP_FAIL
    , SERVICE_SUSPEND_FAIL
    , SERVICE_RESUME_FAIL
    , SERVICE_QUERY_FAIL
};

class ServiceBaseException : public std::exception
{
public:
    char m_buf[150];
    ServiceErrorCode m_error_code;
    DWORD m_last_error;

public:
    ServiceBaseException(const ServiceErrorCode& error_code = ServiceErrorCode::NONE, const char* msg = nullptr)
        : m_error_code(error_code)
        , m_last_error(GetLastError())
        , std::exception(msg)
    {
        sprintf_s(this->m_buf, sizeof(this->m_buf), "%s, error_code : %d, last_error : %d"
                                                    , std::exception::what()
                                                    , (int)this->m_error_code
                                                    , this->m_last_error);
    }

    const char* what() const
    {
        return this->m_buf;
    }
};

class SCMOpenException : public ServiceBaseException
{
public:
    SCMOpenException(const char* msg = nullptr)
        : ServiceBaseException(ServiceErrorCode::SCM_OPEN_FAIL, msg)
    {
    }
};

class ServiceOpenException : public ServiceBaseException
{
public:
    ServiceOpenException(const char* msg = nullptr)
        : ServiceBaseException(ServiceErrorCode::SERVICE_OPEN_FAIL, msg)
    {
    }
};

class ServiceCreateException : public ServiceBaseException
{
public:
    ServiceCreateException(const char* msg = nullptr)
        : ServiceBaseException(ServiceErrorCode::SERVICE_CREATE_FAIL, msg)
    {
    }
};

class ServiceDeleteException : public ServiceBaseException
{
public:
    ServiceDeleteException(const char* msg = nullptr)
        : ServiceBaseException(ServiceErrorCode::SERVICE_DELETE_FAIL, msg)
    {
    }
};

class ServiceControlException : public ServiceBaseException
{
public:
    ServiceControlException(const ServiceErrorCode error_code, const char* msg = nullptr)
        : ServiceBaseException(error_code, msg)
    {
    }
};



class ServiceManager {
private:
    SC_HANDLE m_handle_scm;
    SC_HANDLE m_handle_service;

public:
    ServiceManager()
        : m_handle_scm(nullptr)
        , m_handle_service(nullptr)
    {
    }

    ~ServiceManager()
    {
        this->close_service();
        this->close_scm();
    }

    void open_scm()
    {
        this->m_handle_scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!this->m_handle_scm)
            throw SCMOpenException("scm을 여는데 실패했습니다");
    }

    void close_scm()
    {
        if (this->m_handle_scm != nullptr)
        {
            CloseServiceHandle(this->m_handle_scm);
            this->m_handle_scm = nullptr;
        }
    }

    void open_service(const std::wstring& service_name)
    {
        this->m_handle_service = OpenServiceW(this->m_handle_scm, service_name.c_str(), SERVICE_ALL_ACCESS);
        if (!this->m_handle_service)
            throw ServiceOpenException("서비스를 여는데 실패했습니다");
    }

    void create_service(const std::wstring& service_name, const std::wstring& display_name, const std::wstring& bin_path)
    {
        auto hsvc = CreateServiceW(this->m_handle_scm,
            service_name.c_str(),
            display_name.c_str(),
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            bin_path.c_str(),
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr);

        if (!hsvc)
        {
            if (GetLastError() == ERROR_SERVICE_EXISTS)
            {
                this->open_service(service_name);
                return;
            }

            throw ServiceCreateException("서비스를 만드는데 실패했습니다");
        }

        this->m_handle_service = hsvc;
    }

    void delete_service()
    {
        auto success = DeleteService(this->m_handle_service);

        if (!success && GetLastError() != ERROR_SERVICE_MARKED_FOR_DELETE)
            throw ServiceDeleteException("서비스를 삭제하는데 실패했습니다");
    }

    void close_service()
    {
        if (this->m_handle_service != nullptr)
        {
            CloseServiceHandle(this->m_handle_service);
            this->m_handle_service = nullptr;
        }
    }

    void start()
    {
        auto success = StartServiceW(this->m_handle_service, 0, nullptr);
        if (!success && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
            throw ServiceControlException(ServiceErrorCode::SERVICE_START_FAIL, "서비스를 시작하지 못했습니다");
    }

    void stop()
    {
        SERVICE_STATUS ss;
        if (!ControlService(this->m_handle_service, SERVICE_CONTROL_STOP, &ss))
            throw ServiceControlException(ServiceErrorCode::SERVICE_STOP_FAIL, "서비스를 중지하지 못했습니다");
    }

    void suspend()
    {
        SERVICE_STATUS ss;
        if (!ControlService(this->m_handle_service, SERVICE_CONTROL_PAUSE, &ss))
            throw ServiceControlException(ServiceErrorCode::SERVICE_SUSPEND_FAIL, "서비스를 일시중지하지 못했습니다");
    }

    void resume()
    {
        SERVICE_STATUS ss;
        if (!ControlService(this->m_handle_service, SERVICE_CONTROL_CONTINUE, &ss))
            throw ServiceControlException(ServiceErrorCode::SERVICE_RESUME_FAIL, "서비스를 재개하지 못했습니다");
    }

    void status(SERVICE_STATUS& status)
    {
        if (!QueryServiceStatus(this->m_handle_service, &status))
            throw ServiceControlException(ServiceErrorCode::SERVICE_QUERY_FAIL, "서비스 상태를 가져오지 못했습니다");
    }
};