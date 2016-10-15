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

#pragma once

#include <Windows.h>

#include <vector>
#include <memory>
#include <array>

class AttributeHandleList
{
public:
    AttributeHandleList();
    explicit AttributeHandleList(std::vector<HANDLE> handle_list);
    LPPROC_THREAD_ATTRIBUTE_LIST    get_attribute_list_ptr() const { return m_pAttributeList.get(); }
private:
    // note: order of the members matters (because of destruction order)
    std::unique_ptr<HANDLE[]>       m_handle_store;
    typedef std::unique_ptr<_PROC_THREAD_ATTRIBUTE_LIST, void (*)(LPPROC_THREAD_ATTRIBUTE_LIST)> unique_attribute_list_ptr;
    unique_attribute_list_ptr       m_pAttributeList;
};

class StdRedirects
{
public:
    enum role_e { REDIR_STDIN, REDIR_STDOUT, REDIR_STDERR };
public:
    StdRedirects() noexcept;
    ~StdRedirects() noexcept;
    void close() noexcept;
    StdRedirects(const StdRedirects&) = delete;
    StdRedirects& operator =(const StdRedirects&) = delete;
    void adopt_handle(role_e role, HANDLE h);
    void set_to_nul(role_e role);
    void set_same_as_other(role_e role, role_e other);
    AttributeHandleList attribute_handle_list() const;
    HANDLE get_handle(role_e role) const;
private:
    std::array<HANDLE, 3>  m_handleOwned;
    std::array<HANDLE, 3>  m_handle;
};
