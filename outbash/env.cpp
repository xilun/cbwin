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

#include <memory>
#include <string>
#include <stdexcept>
#include <cwchar>

#include "env.h"
#include "utf.h"

const from_system_type from_system{};

using std::size_t;

bool CompareEnvVarName::operator()(const std::wstring& a, const std::wstring& b) const
{
    return CSTR_LESS_THAN == CompareStringOrdinal(a.c_str(), (int)a.length(), b.c_str(), (int)b.length(), TRUE);
}

EnvVars::EnvVars(from_system_type)
{
    std::unique_ptr<wchar_t, decltype(::FreeEnvironmentStringsW) *> uwinenv(::GetEnvironmentStringsW(), &::FreeEnvironmentStringsW);

    for (wchar_t* winenv = uwinenv.get(); *winenv; winenv += std::wcslen(winenv) + 1) {
        wchar_t* where = std::wcschr(winenv + 1, L'=');
        if (where == nullptr) // wtf?
            continue;
        m_env[std::wstring(winenv, where - winenv)] = where + 1;
    }
}

std::wstring EnvVars::get_environment_block() const
{
    std::wstring result;
    for (const auto& kv : m_env) {
        result.append(kv.first);
        result.append(1, L'=');
        result.append(kv.second);
        result.append(1, L'\0');
    }
    result.append(1, L'\0');
    return result;
}

void EnvVars::set_from_utf8(const char* s)
{
    std::wstring ws = utf::widen(s);
    if (ws.empty())
        throw std::runtime_error("got empty env string");

    wchar_t* where = std::wcschr(&ws[1], L'=');
    if (where == nullptr)
        throw std::runtime_error("env key value separator '=' not found");

    if (where[1] != L'\0')
        m_env[std::wstring(&ws[0], where - &ws[0])] = where + 1;
    else
        m_env.erase(std::wstring(&ws[0], where - &ws[0]));
}
