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

#include <Windows.h>

#include <array>
#include "my.mutex.h"

#include "console.h"
#include "win_except.h"


namespace {

class CConsoleMode {
public:
    CConsoleMode(DWORD std_h)
      : m_handle(::GetStdHandle(std_h)),
        m_mutex{},
        m_orig_mode(0),
        m_saved_mode(0),
        m_orig_users(0),
        m_managed(!!::GetConsoleMode(m_handle, &m_orig_mode))
    { }
    void get_orig()
    {
        if (m_managed) {
            my::lock_guard<my::mutex> lock(m_mutex);
            if (++m_orig_users == 1) {
                if (!::GetConsoleMode(m_handle, &m_saved_mode)) {
                    Win32_perror("GetConsoleMode (CConsoleMode::get_orig)");
                    m_saved_mode = m_orig_mode;
                }
                if (!::SetConsoleMode(m_handle, m_orig_mode)) {
                    Win32_perror("SetConsoleMode (CConsoleMode::get_orig)");
                }
            }
        }
    }
    void put_orig()
    {
        if (m_managed) {
            my::lock_guard<my::mutex> lock(m_mutex);
            if (--m_orig_users == 0) {
                if (!::SetConsoleMode(m_handle, m_saved_mode)) {
                    Win32_perror("SetConsoleMode (CConsoleMode::put_orig)");
                }
            }
        }
    }
    bool is_managed() const { return m_managed; }
private:
    const HANDLE    m_handle;
    my::mutex       m_mutex;
    DWORD           m_orig_mode;
    DWORD           m_saved_mode;
    int             m_orig_users;
    const bool      m_managed;
};

} // namespace


class CInOutConsoleModes::CInOutConsoleModesImpl {
public:
    CInOutConsoleModesImpl()
      : m_console_modes{ { STD_INPUT_HANDLE, STD_OUTPUT_HANDLE } },
        m_mask_filter(  (m_console_modes[DIR_CONSOLE_IN].is_managed()  ? DIR_CONSOLE_IN_BIT  : 0)
                      | (m_console_modes[DIR_CONSOLE_OUT].is_managed() ? DIR_CONSOLE_OUT_BIT : 0)) {}
    std::array<CConsoleMode, 2> m_console_modes;
    const std::uint32_t         m_mask_filter;
};

CInOutConsoleModes::CInOutConsoleModes() = default;
CInOutConsoleModes::~CInOutConsoleModes() = default;

void CInOutConsoleModes::initialize_from_current_modes()
{
    m_pimpl.reset(new CInOutConsoleModesImpl());
}

CInOutConsoleModes::CStateSwitchConsoleModes CInOutConsoleModes::get_orig_for(dir_console_mask_e msk)
{
    return CStateSwitchConsoleModes(m_pimpl.get(), (std::uint32_t)msk & m_pimpl->m_mask_filter);
}

void CInOutConsoleModes::CStateSwitchConsoleModes::get_orig()
{
    if (m_modes_impl) {
        std::uint32_t target = m_mask & ~m_switched;
        if (target & DIR_CONSOLE_IN_BIT) {
            m_modes_impl->m_console_modes.at(DIR_CONSOLE_IN).get_orig();
            m_switched |= DIR_CONSOLE_IN_BIT;
        }
        if (target & DIR_CONSOLE_OUT_BIT) {
            m_modes_impl->m_console_modes.at(DIR_CONSOLE_OUT).get_orig();
            m_switched |= DIR_CONSOLE_OUT_BIT;
        }
    }
}

void CInOutConsoleModes::CStateSwitchConsoleModes::put_orig()
{
    if (m_modes_impl) {
        std::uint32_t target = m_mask & m_switched;
        if (target & DIR_CONSOLE_IN_BIT) {
            m_modes_impl->m_console_modes.at(DIR_CONSOLE_IN).put_orig();
            m_switched &= ~DIR_CONSOLE_IN_BIT;
        }
        if (target & DIR_CONSOLE_OUT_BIT) {
            m_modes_impl->m_console_modes.at(DIR_CONSOLE_OUT).put_orig();
            m_switched &= ~DIR_CONSOLE_OUT_BIT;
        }
    }
}
