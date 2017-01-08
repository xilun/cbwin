/*
 * Copyright(c) 2016-2017  Guillaume Knispel <xilun0@gmail.com>
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

#pragma once

#include <map>
#include <string>

struct from_system_type { };
extern const from_system_type from_system;

struct CompareEnvVarName {
    bool operator()(const std::wstring& a, const std::wstring& b) const;
};

class EnvVars
{
public:
    EnvVars() {}
    explicit EnvVars(from_system_type);
    std::wstring get_environment_block() const;
    void set_from_utf8(const char* s);
    // get(name) returns the value of the corresponding environment variable,
    // or an empty string if not found
    std::wstring get(const wchar_t* name) const;
private:
    std::map<std::wstring, std::wstring, CompareEnvVarName> m_env;
};

class Env {
    std::wstring get_comspec() const;
    std::wstring get_module_windows_path() const;
public:
    Env();
// attributes:
    EnvVars initial_vars;
    std::wstring windows_directory;
    std::wstring system_directory;
    std::wstring comspec;
    std::wstring userprofile;
    std::wstring module_directory;
    std::wstring module_windows_path;
};
