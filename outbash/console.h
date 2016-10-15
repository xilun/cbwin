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

#include <cstdint>
#include <cassert>

class CInOutConsoleModes {
    class CInOutConsoleModesImpl;

public:
    enum dir_console_e { DIR_CONSOLE_IN = 0, DIR_CONSOLE_OUT = 1 };
    enum dir_console_mask_e { DIR_CONSOLE_IN_BIT=(1<<DIR_CONSOLE_IN), DIR_CONSOLE_OUT_BIT=(1<<DIR_CONSOLE_OUT),
                              FULL_MASK = DIR_CONSOLE_IN_BIT | DIR_CONSOLE_OUT_BIT };

    class CStateSwitchConsoleModes {
        friend class CInOutConsoleModes;
    public:
        CStateSwitchConsoleModes() : m_modes_impl(nullptr), m_mask(0), m_switched(0) {}
        CStateSwitchConsoleModes(CStateSwitchConsoleModes&& other)
          : m_modes_impl(other.m_modes_impl),
            m_mask(other.m_mask),
            m_switched(other.m_switched)
        {
            other.clear();
        }
        CStateSwitchConsoleModes& operator=(CStateSwitchConsoleModes&& other)
        {
            assert(m_modes_impl == nullptr);
            m_modes_impl = other.m_modes_impl;
            m_mask = other.m_mask;
            m_switched = other.m_switched;
            other.clear();
            return *this;
        }
        void get_orig();
        void put_orig();
        ~CStateSwitchConsoleModes() { put_orig(); }
    private:
        CStateSwitchConsoleModes(CInOutConsoleModesImpl* modes_impl, std::uint32_t mask)
          : m_modes_impl(modes_impl), m_mask(mask), m_switched(0)
        {
            get_orig();
        }
        void clear()
        {
            m_modes_impl = nullptr;
            m_mask = 0;
            m_switched = 0;
        }
    private:
        CInOutConsoleModesImpl *m_modes_impl;
        std::uint32_t           m_mask;
        std::uint32_t           m_switched;
    };

    CInOutConsoleModes();
    void initialize_from_current_modes();
    CStateSwitchConsoleModes get_orig_for(dir_console_mask_e msk);
    ~CInOutConsoleModes();

private:
    std::unique_ptr<CInOutConsoleModesImpl> m_pimpl;
};
