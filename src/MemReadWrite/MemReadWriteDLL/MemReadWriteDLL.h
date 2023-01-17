// 다음 ifdef 블록은 DLL에서 내보내는 작업을 더 간소화하는 매크로를 만드는
// 표준 방법입니다. 이 DLL에 들어 있는 파일은 모두 명령줄에 정의된 MEMREADWRITEDLL_EXPORTS 기호로
// 컴파일됩니다. 이 DLL을 사용하는 프로젝트에서는 이 기호를 정의할 수 없습니다.
// 이렇게 하면 소스 파일에 이 파일이 포함된 다른 모든 프로젝트에서는
// MEMREADWRITEDLL_API 함수를 DLL에서 가져오는 것으로 표시되는 반면, 이 DLL에서는
// 이 매크로로 정의된 기호가 내보내지는 것으로 표시됩니다.

#include <exception>
#include <Windows.h>


#ifdef MEMREADWRITEDLL_EXPORTS
#define MEMREADWRITEDLL_API __declspec(dllexport)
#else
#define MEMREADWRITEDLL_API __declspec(dllimport)
#endif


enum class MemErrorCode
{
    NONE
    , DLL_HANDLE_IS_NULL
    , FILE_SAVE_FAIL
    , DRIVER_INSTALL_FAIL
    , DRIVER_UNINSTALL_FAIL
    , DRIVER_OPEN_FAIL
    , DRIVER_IO_FAIL
};


namespace mem
{
    class BaseException : public std::exception
    {
    public:
        char m_buf[150];
        MemErrorCode m_error_code;
        int m_extra_error_code;
        DWORD m_last_error;

    public:
        BaseException(const MemErrorCode error_code, const char* msg = nullptr, int extra_error_code = 0);
        const char* what() const;
    };


    class DriverInstallException : public BaseException
    {
    public:
        DriverInstallException(const MemErrorCode error_code, const char* msg = nullptr, int extra_error_code = 0);
    };


    class DriverOpenException : public BaseException
    {
    public:
        DriverOpenException(const char* msg = nullptr);
    };

    
    class DriverIOException : public BaseException
    {
    public:
        DriverIOException(const char* msg = nullptr);
    };


    MEMREADWRITEDLL_API void install_driver();
    MEMREADWRITEDLL_API void uninstall_driver();

    class MEMREADWRITEDLL_API DriverHelper
    {
    private:
        ULONG m_pid;
        HANDLE m_driver;

    public:
        DriverHelper(ULONG pid);
        virtual ~DriverHelper();

        ULONGLONG read_data(ULONGLONG address, ULONG buf_size);

        BYTE read_byte(ULONGLONG address);
        WORD read_word(ULONGLONG address);
        DWORD read_dword(ULONGLONG address);
        FLOAT read_float(ULONGLONG address);
        ULONGLONG read_ulonglong(ULONGLONG address);
    };
}


extern "C"
{
    //MEMREADWRITEDLL_API void install_driver();
    //MEMREADWRITEDLL_API void uninstall_driver();
}