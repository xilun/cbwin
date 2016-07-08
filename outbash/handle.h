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

#include "win_except.h"

class CUniqueHandle
{
public:
    CUniqueHandle() noexcept : m_handle(NULL) {}
    explicit CUniqueHandle(HANDLE h) noexcept : m_handle(h) {}
    CUniqueHandle(HANDLE h, const char* checked_origin) : m_handle(h)
    {
        if (!is_valid())
            throw_last_error(checked_origin);
    }
    CUniqueHandle(const CUniqueHandle&) = delete;
    CUniqueHandle& operator=(const CUniqueHandle&) = delete;
    CUniqueHandle(CUniqueHandle&& other) noexcept : m_handle(other.m_handle) { other.m_handle = NULL; }
    CUniqueHandle& operator=(CUniqueHandle&& other) noexcept
    {
        if (this != &other) {
            if (is_valid()) ::CloseHandle(m_handle);
            m_handle = other.m_handle;
            other.m_handle = NULL;
        }
        return *this;
    }
    ~CUniqueHandle() noexcept { if (is_valid()) ::CloseHandle(m_handle); }
    void close() noexcept
    {
        if (is_valid()) {
            ::CloseHandle(m_handle);
            m_handle = NULL;
        }
    }
    HANDLE get_checked() const
    {
        if (!is_valid()) {
            ::SetLastError(ERROR_INVALID_HANDLE);
            throw_last_error("CUniqueHandle::get_checked");
        }
        return m_handle;
    }
    HANDLE get_unchecked() const noexcept { return m_handle; }
    bool is_valid() const noexcept
    {
        return m_handle != NULL && m_handle != INVALID_HANDLE_VALUE;
    }
private:
    HANDLE m_handle;
};
