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

#include <system_error>
#include <cstdio>

#include "win_except.h"

void throw_last_error(const char* what)
{
    throw std::system_error(std::error_code(::GetLastError(), std::system_category()), what);
}

void throw_system_error(const char* what, DWORD system_error_code)
{
    throw std::system_error(std::error_code(system_error_code, std::system_category()), what);
}

void Win32_perror(const char* what)
{
    const int errnum = ::GetLastError();
    const bool what_present = (what && *what);

    WCHAR *str;
    DWORD nbWChars = ::FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER
                                      | FORMAT_MESSAGE_FROM_SYSTEM
                                      | FORMAT_MESSAGE_IGNORE_INSERTS
                                      | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                                      nullptr, (DWORD)errnum, 0, (LPWSTR)&str,
                                      0, nullptr);
    if (nbWChars == 0) {
        std::fprintf(stderr, "%s%swin32 error %d\n",
                     what_present ? what : "",
                     what_present ? ": " : "",
                     errnum);
    } else {
        std::fprintf(stderr, "%s%s%ls\n",
                     what_present ? what : "",
                     what_present ? ": " : "",
                     str);
        ::LocalFree(str);
    }
    ::SetLastError(errnum);
}
