/*
 * Copyright(c) 2016  Guillaume Knispel <xilun0@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <Windows.h>
#include <sddl.h>

#include <string>
#include <memory>

#include "win_except.h"
#include "handle.h"


namespace {


static PSID psid_from_token_info_ptr(TOKEN_USER* token_user)
{
    return token_user->User.Sid;
}

static PSID psid_from_token_info_ptr(TOKEN_PRIMARY_GROUP* token_primary_group)
{
    return token_primary_group->PrimaryGroup;
}

static PSID psid_from_token_info_ptr(TOKEN_MANDATORY_LABEL* token_mandatory_label)
{
    return token_mandatory_label->Label.Sid;
}

template <typename TTokenType, TOKEN_INFORMATION_CLASS TTokenInfoClass>
static std::string sid_from_token_info(HANDLE hToken)
{
    std::unique_ptr<TTokenType, decltype(std::free) *> pTokenInfo{ nullptr, &std::free };
    DWORD length;
    if (!::GetTokenInformation(hToken, TTokenInfoClass, (LPVOID)pTokenInfo.get(), 0, &length)) {
        DWORD last_error = ::GetLastError();
        if (last_error != ERROR_INSUFFICIENT_BUFFER)
            throw_system_error("sid_from_token_info: GetTokenInformation (get length)", last_error);
        pTokenInfo.reset((TTokenType*)std::malloc(length));
    }
    if (!::GetTokenInformation(hToken, TTokenInfoClass, (LPVOID)pTokenInfo.get(), length, &length))
        throw_last_error("sid_from_token_info: GetTokenInformation (get info)");

    char* cstr_sid;
    if (!::ConvertSidToStringSidA(psid_from_token_info_ptr(pTokenInfo.get()), &cstr_sid))
        throw_last_error("sid_from_token_info: ConvertSidToStringSid");
    return std::unique_ptr<char, decltype(::LocalFree) *>{ cstr_sid, &::LocalFree }.get();
}

static CUniqueHandle get_current_process_token()
{
    HANDLE hToken;
    if (!::OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        throw_last_error("get_current_process_token: OpenProcessToken");
    return CUniqueHandle(hToken);
}

static std::string sddl_allow_user_with_integrity()
{
    CUniqueHandle token = get_current_process_token();
    std::string user_sid = sid_from_token_info<TOKEN_USER, TokenUser>(token.get_checked());
    // The primary group is essentially useless, except it is mandatory:
    std::string primary_group = sid_from_token_info<TOKEN_PRIMARY_GROUP, TokenPrimaryGroup>(token.get_unchecked());
    std::string mandatory_label = sid_from_token_info<TOKEN_MANDATORY_LABEL, TokenIntegrityLevel>(token.get_unchecked());
    return "O:" + user_sid
         + "G:" + primary_group
         + "D:(A;;GA;;;" + user_sid + ")"
         + "S:(ML;;NWNRNX;;;" + mandatory_label + ")";
}

typedef std::unique_ptr<SECURITY_DESCRIPTOR, decltype(::LocalFree) *> TUniqueSecDescBase;
class CUniqueSecDesc : public TUniqueSecDescBase
{
public:
    CUniqueSecDesc(PSECURITY_DESCRIPTOR pSecDesc) : TUniqueSecDescBase((SECURITY_DESCRIPTOR*)pSecDesc, &::LocalFree) { }
};

static PSECURITY_DESCRIPTOR create_user_only_sd()
{
    std::string sddl = sddl_allow_user_with_integrity();
    //printf("SDDL: %s\n", sddl.c_str());
    PSECURITY_DESCRIPTOR pRawSecDesc;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl.c_str(),
                                                                SDDL_REVISION_1,
                                                                &pRawSecDesc,
                                                                NULL))
        throw_last_error("ConvertStringSecurityDescriptorToSecurityDescriptor");
    return pRawSecDesc;
}

static CUniqueSecDesc g_user_sd(create_user_only_sd());

//<rant>
// As you are reading this, I would like to take the opportunity to tell you that AccessCheck() and its
// friends are crap.
// I mean, not only the exact behavior is insane, but the MSDN doc fails to describe it in a useful way,
// and MSDN examples show that not even MS know how it is supposed to be used. As usual, Wine has been
// useful to sort out this issue.
// For crying out loud, if you wrote this API or the documentation, and think this is proper, please
// either change your career to something that actually interest you and you are good at, or at least
// take a look at a real doc like any random Posix man page or the C++ standard, or something like that.
// (Not that Posix or C++ are actually very good, just that the Win API and MSDN doc are often pretty bad...)
//</rant>

// if you don't care about PrivilegeSet but don't want to risk to randomly fail:
static
BOOL access_check_simpler(_In_   PSECURITY_DESCRIPTOR  pSecurityDescriptor,
                          _In_   HANDLE                ClientToken,
                          _In_   DWORD                 DesiredAccess,
                          _In_   PGENERIC_MAPPING      GenericMapping,
                          _Out_  LPDWORD               GrantedAccess,
                          _Out_  LPBOOL                AccessStatus)
{
    PRIVILEGE_SET privilege_set;
    DWORD privilege_set_length = sizeof(privilege_set);
    BOOL result = ::AccessCheck(pSecurityDescriptor, ClientToken, DesiredAccess, GenericMapping,
                                &privilege_set, &privilege_set_length, GrantedAccess, AccessStatus);
    if ( result
         || ::GetLastError() != ERROR_INSUFFICIENT_BUFFER
         || privilege_set_length <= sizeof(privilege_set))
        return result;

    PPRIVILEGE_SET pprivilege_set = (PPRIVILEGE_SET)std::malloc(privilege_set_length);
    if (!pprivilege_set) {
        ::SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        *GrantedAccess = 0;
        *AccessStatus = FALSE;
        return FALSE;
    }
    result = ::AccessCheck(pSecurityDescriptor, ClientToken, DesiredAccess, GenericMapping,
                           pprivilege_set, &privilege_set_length, GrantedAccess, AccessStatus);
    DWORD last_error = ::GetLastError();
    std::free(pprivilege_set);
    ::SetLastError(last_error);
    return result;
}

static GENERIC_MAPPING StdGenericMapping = {
    STANDARD_RIGHTS_READ,
    STANDARD_RIGHTS_WRITE,
    STANDARD_RIGHTS_EXECUTE,
    STANDARD_RIGHTS_REQUIRED,
};


} // namespace


bool check_caller_process_allowed(const CUniqueHandle& hProcess)
{
    if (!hProcess.is_valid())
        return false;

    HANDLE hToken = nullptr;
    if (!::OpenProcessToken(hProcess.get_checked(), TOKEN_DUPLICATE, &hToken)) {
        Win32_perror("check_caller_process_allowed: OpenProcessToken");
        return false;
    }
    HANDLE hImpersonationToken = nullptr;
    if (!::DuplicateTokenEx(hToken, TOKEN_QUERY, NULL, SecurityIdentification, TokenImpersonation, &hImpersonationToken)) {
        Win32_perror("check_caller_process_allowed: DuplicateTokenEx");
        ::CloseHandle(hToken);
        return false;
    }
    ::CloseHandle(hToken); hToken = nullptr;

    BOOL access_status = FALSE;
    DWORD GrantedAccess = 0;
    if (!access_check_simpler(g_user_sd.get(), hImpersonationToken, STANDARD_RIGHTS_EXECUTE, &StdGenericMapping, &GrantedAccess, &access_status)) {
        Win32_perror("check_caller_process_allowed: AccessCheck");
        access_status = FALSE;
    }
    ::CloseHandle(hImpersonationToken);

    return !!access_status;
}
