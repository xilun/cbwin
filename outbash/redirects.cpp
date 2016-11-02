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

#include <algorithm>
#include <cstring>

#include "redirects.h"
#include "win_except.h"

static void attribute_list_deleter(LPPROC_THREAD_ATTRIBUTE_LIST attribute_list)
{
    DWORD ec = ::GetLastError();
    ::DeleteProcThreadAttributeList(attribute_list);
    delete[] reinterpret_cast<char*>(attribute_list);
    ::SetLastError(ec);
}

AttributeHandleList::AttributeHandleList()
    : m_handle_store(nullptr),
      m_pAttributeList(nullptr, attribute_list_deleter)
{}

AttributeHandleList::AttributeHandleList(std::vector<HANDLE> handle_list)
    : m_handle_store(nullptr),
      m_pAttributeList(nullptr, attribute_list_deleter)
{
    SIZE_T size = 0;
    BOOL ok = ::InitializeProcThreadAttributeList(NULL, 1, 0, &size)
              || ::GetLastError() == ERROR_INSUFFICIENT_BUFFER;
    if (!ok) throw_last_error("InitializeProcThreadAttributeList(NULL, ...) failed");

    m_pAttributeList.reset(reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(new char[size]));
    ok = ::InitializeProcThreadAttributeList(m_pAttributeList.get(), 1, 0, &size);
    if (!ok) {
        delete[] reinterpret_cast<char*>(m_pAttributeList.release());
        throw_last_error("InitializeProcThreadAttributeList() failed");
    }

    // WARNING: O(n^2), ok for small lists:
    for (size_t i = 0; i < handle_list.size(); i++) {
        size_t next = i + 1;
        while (1) {
            auto it = std::find(handle_list.begin() + next, handle_list.end(), handle_list.at(i));
            if (it == handle_list.end())
                break;
            next = it - handle_list.begin();
            handle_list.erase(it);
        }
    }

    m_handle_store.reset(new HANDLE[handle_list.size()]);
    if (handle_list.size()) { // C++ is evil:
        // data() is not undefined behavior even if handle_list is empty,
        // however it is allowed to be nullptr in this case, while memcpy
        // requires the src to never be nullptr, even for a zero size.
        std::memcpy(m_handle_store.get(), handle_list.data(), handle_list.size() * sizeof(HANDLE));
    }

    ok = ::UpdateProcThreadAttribute(m_pAttributeList.get(),
                    0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    (PVOID)m_handle_store.get(),
                    handle_list.size() * sizeof(HANDLE),
                    NULL, NULL);
    if (!ok) throw_last_error("UpdateProcThreadAttribute() failed");
}

static void free_handle(HANDLE& h) noexcept
{
    if (h != NULL && h != INVALID_HANDLE_VALUE) {
        ::CloseHandle(h);
        h = NULL;
    }
}

static HANDLE open_inheritable_nul(bool output)
{
    SECURITY_ATTRIBUTES sec_attr = { sizeof(sec_attr), NULL, TRUE };
    HANDLE hret = ::CreateFileA("nul",
                                output ? GENERIC_WRITE : GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                &sec_attr,
                                OPEN_EXISTING,
                                0,
                                NULL);
    if (hret == NULL || hret == INVALID_HANDLE_VALUE)
        throw_last_error("CreateFile(\"nul\",...) failed");
    return hret;
}

static const HANDLE inheritable_nul_input = open_inheritable_nul(false);
static const HANDLE inheritable_nul_output = open_inheritable_nul(true);

StdRedirects::StdRedirects() noexcept : m_handleOwned{}
{
    m_handle[REDIR_STDIN] = ::GetStdHandle(STD_INPUT_HANDLE);
    m_handle[REDIR_STDOUT] = ::GetStdHandle(STD_OUTPUT_HANDLE);
    m_handle[REDIR_STDERR] = ::GetStdHandle(STD_ERROR_HANDLE);
}

StdRedirects::~StdRedirects() noexcept
{
    close();
}

void StdRedirects::close() noexcept
{
    free_handle(m_handleOwned[REDIR_STDIN]);
    free_handle(m_handleOwned[REDIR_STDOUT]);
    free_handle(m_handleOwned[REDIR_STDERR]);
}

void StdRedirects::adopt_handle(role_e role, HANDLE h)
{
    m_handleOwned.at(role) = h;
    m_handle.at(role) = h;
}

void StdRedirects::set_to_nul(role_e role)
{
    m_handle.at(role) = (role == REDIR_STDIN) ? inheritable_nul_input : inheritable_nul_output;
}

void StdRedirects::set_same_as_other(role_e role, role_e other)
{
    m_handle.at(role) = m_handle.at(other);
}

HANDLE StdRedirects::get_handle(role_e role) const
{
    return m_handle.at(role);
}

AttributeHandleList StdRedirects::attribute_handle_list() const
{
    return AttributeHandleList(std::vector<HANDLE>(m_handle.begin(), m_handle.end()));
}
