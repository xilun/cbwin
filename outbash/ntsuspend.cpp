#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
# include <Windows.h>
# include <winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#include <cstdio>

#include "ntsuspend.h"

void DisplayNTError(const char* what, LONG NTStatus)
{
    const bool what_present = (what && *what);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    WCHAR *str;
    DWORD nbWChars = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER
                                    | FORMAT_MESSAGE_FROM_SYSTEM
                                    | FORMAT_MESSAGE_FROM_HMODULE
                                    | FORMAT_MESSAGE_IGNORE_INSERTS,
                                    ntdll,
                                    (DWORD)NTStatus,
                                    0, //MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                    (LPWSTR)&str,
                                    0,
                                    NULL);
    if (nbWChars == 0) {
        std::fprintf(stderr, "%s: NT Error Status: 0x%lX\n", what, NTStatus);
    } else {
        std::fprintf(stderr, "%s: %S\n", what, str);
        LocalFree(str);
    }
}

typedef LONG (NTAPI *pNtSuspendProcess )( HANDLE ProcessHandle );
pNtSuspendProcess NtSuspendProcess;
typedef LONG (NTAPI *pNtResumeProcess )( HANDLE ProcessHandle );
pNtResumeProcess NtResumeProcess;

int ImportNtProcess(void)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
        return 0;

    NtSuspendProcess = (pNtSuspendProcess)GetProcAddress(ntdll, "NtSuspendProcess");
    if (NtSuspendProcess)
        NtResumeProcess = (pNtResumeProcess)GetProcAddress(ntdll, "NtResumeProcess");

    return !!(NtSuspendProcess && NtResumeProcess);
}

bool NT_Suspend(HANDLE hProcess)
{
    LONG status = NtSuspendProcess(hProcess);
    if (!NT_SUCCESS(status)) {
        DisplayNTError("outbash: NtSuspendProcess", status);
        return false;
    }
    return true;
}

bool NT_Resume (HANDLE hProcess)
{
    LONG status = NtResumeProcess(hProcess);
    if (!NT_SUCCESS(status)) {
        DisplayNTError("outbash: NtResumeProcess", status);
        return false;
    }
    return true;
}
