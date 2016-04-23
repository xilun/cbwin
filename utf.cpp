/*
 * Copyright(c) 2016  Guillaume Knispel <xilun0@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files(the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions :
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <Windows.h>

#include "utf.h"


// NOTE: the only sane thing to do, provided other components of the system
// do likewise, would be to convert to/from WTF-8 instead of UTF-8.
// I've not yet tested what WSL do. I guess that for now just using
// MultiByteToWideChar and WideCharToMultiByte would be good enough
// in > 99% of use cases.
// However what those functions do precisely even when limited to UTF is
// extremely unclear (there are some quite not specified normalization
// stuff that could also be involved, or maybe not?) so in a future version
// it might be useful to try to qualify more exactly what WSL does, and
// maybe replace the code here to do exactly the same thing.


namespace utf
{


std::string narrow(const wchar_t* s)
{
    int res_size = WideCharToMultiByte(CP_UTF8, 0, s, -1, NULL, 0, NULL, NULL);
    if (res_size <= 0)
        throw conversion_error();
    std::string result(res_size, ' ');
    int r = WideCharToMultiByte(CP_UTF8, 0,
                                s, -1,
                                &result[0], res_size,
                                NULL, NULL);
    if (r <= 0)
        throw conversion_error();
    result.resize(r - 1);
    return result;
}

std::string narrow(const std::wstring& s)
{
    if (s.size() * 3 >= INT_MAX)
        throw conversion_error();
    std::string result(s.size() * 3 + 1, ' ');
    int r = WideCharToMultiByte(CP_UTF8, 0,
                                s.c_str(), (int)s.size() + 1,
                                &result[0], (int)s.size() * 3 + 1,
                                NULL, NULL);
    if (r <= 0)
        throw conversion_error();
    result.resize(r - 1);
    return result;
}

std::wstring widen(const char* s)
{
    int res_size = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (res_size <= 0)
        throw conversion_error();
    std::wstring result(res_size, L' ');
    int r = MultiByteToWideChar(CP_UTF8, 0, s, -1, &result[0], res_size);
    if (r <= 0)
        throw conversion_error();
    result.resize(r - 1);
    return result;
}

std::wstring widen(const std::string& s)
{
    if (s.size() >= INT_MAX)
        throw conversion_error();
    std::wstring result(s.size() + 1, L' ');
    int r = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size() + 1, &result[0], (int)s.size() + 1);
    if (r <= 0)
        throw conversion_error();
    result.resize(r - 1);
    return result;
}


}
