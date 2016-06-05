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

// WARNING: This program is unsafe if you have multiple users/accounts on the same computer!
// It trusts anything that can connect in TCP to 127.0.0.1

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

#include <memory>
#include <thread>
#include <vector>
#include <string>
#include <algorithm>
#include <exception>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <clocale>
#include <mbctype.h>

#include "utf.h"
#include "env.h"
#include "process.h"
#include "win_except.h"

#pragma comment(lib, "Ws2_32.lib")

using std::size_t;
using std::uint16_t;

static EnvVars initial_env_vars(from_system);

template <typename CharT>
static bool is_ascii_letter(CharT c)
{
    return (c >= (CharT)'a' && c <= (CharT)'z') || (c >= (CharT)'A' && c <= (CharT)'Z');
}

template <typename CharT>
static CharT to_ascii_lower(CharT c)
{
    return (c >= (CharT)'A' && c <= (CharT)'Z') ? c - (CharT)'A' + (CharT)'a' : c;
}

static bool is_cmd_line_sep(wchar_t c)
{
    return c == L' ' || c == L'\t';
}

static bool startswith(const std::string& s, const std::string& start)
{
    return !s.compare(0, start.size(), start);
}

static const wchar_t* get_cmd_line_params()
{
    const wchar_t* p = GetCommandLineW();
    if (p == nullptr)
        return L"";
    // we use the same rules as the CRT parser to delimit argv[0]:
    for (bool quoted = false; *p != L'\0' && (quoted || !is_cmd_line_sep(*p)); p++) {
        if (*p == L'"')
            quoted = !quoted;
    }
    while (is_cmd_line_sep(*p))
        p++;
    return p; // pointer to the first param (if any) in the command line
}

static std::wstring get_comspec()
{
    wchar_t buf[MAX_PATH+1];
    UINT res = ::GetEnvironmentVariableW(L"ComSpec", buf, MAX_PATH+1);
    if (res == 0 && ::GetLastError() == ERROR_ENVVAR_NOT_FOUND) {
        res = ::GetSystemDirectoryW(buf, MAX_PATH+1);
        if (res == 0 || res > MAX_PATH) { std::fprintf(stderr, "outbash: GetSystemDirectory error\n"); std::abort(); }
        return buf + std::wstring(L"\\cmd.exe");
    } else {
        if (res == 0 || res > MAX_PATH) { std::fprintf(stderr, "outbash: GetEnvironmentVariable ComSpec error\n"); std::abort(); }
        return buf;
    }
}
static const std::wstring comspec = get_comspec();

static void Win32_perror(const char* what)
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
        std::fprintf(stderr, "%s%s%S\n",
                     what_present ? what : "",
                     what_present ? ": " : "",
                     str);
        ::LocalFree(str);
    }
    ::SetLastError(errnum);
}

int wstr_case_ascii_ncmp(const wchar_t* s1, const wchar_t* s2, size_t n)
{
    wchar_t c1, c2;
    do {
        c1 = *s1++;
        c2 = *s2++;
        if (n-- == 0)
            c1 = L'\0';
    } while (c1 != L'\0' && to_ascii_lower(c1) == to_ascii_lower(c2));

    return ((uint16_t)c1 > (uint16_t)c2) ? 1
        : (c1 == c2 ? 0
           : -1);
}

// PathIsRelative is, ahem, ... interesting? (like a lot of Win32 stuff, actually)
// So we implement our own (hopefully) non crazy check:
static bool path_is_really_absolute(const wchar_t* path)
{
    if (*path == L'\\')
        return true;
    if (is_ascii_letter(path[0]) && path[1] == L':' && path[2] == L'\\')
        return true;
    return false;
}

static int start_command(std::wstring cmdline,
                         const wchar_t* dir,
                         EnvVars* vars,
                         StdRedirects* redirs,
                         PROCESS_INFORMATION& out_pi)
{
    STARTUPINFOEXW si;

    ZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(si);
    ZeroMemory(&out_pi, sizeof(out_pi));

    const wchar_t* wdir = nullptr;
    if (dir != nullptr && *dir != L'\0') {
        // CreateProcess will happily use a relative, but we don't want to
        if (!path_is_really_absolute(dir)) {
            std::fprintf(stderr, "outbash: start_command: non-absolute directory parameter: %S\n", dir);
            return 1;
        }
        wdir = dir;
    }

    const wchar_t* module = NULL;
    if (wstr_case_ascii_ncmp(cmdline.c_str(), L"cmd", 3) == 0 && (is_cmd_line_sep(cmdline[3]) || cmdline[3] == L'\0'))
        module = comspec.c_str();

    const wchar_t* env = nullptr;
    std::wstring wbuf;
    if (vars) {
        wbuf = vars->get_environment_block();
        env = &wbuf[0];
    }

    AttributeHandleList ahl;
    BOOL inherit_handles = FALSE;
    if (redirs) {
        inherit_handles = TRUE;
        si.StartupInfo.hStdInput = redirs->get_handle(StdRedirects::REDIR_STDIN);
        si.StartupInfo.hStdOutput = redirs->get_handle(StdRedirects::REDIR_STDOUT);
        si.StartupInfo.hStdError = redirs->get_handle(StdRedirects::REDIR_STDERR);
        si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        ahl = redirs->attribute_handle_list();
        si.lpAttributeList = ahl.get_attribute_list_ptr();
    }
    if (!::CreateProcessW(module, &cmdline[0], NULL, NULL, inherit_handles,
                          CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                          (LPVOID)env, wdir, (STARTUPINFOW*)&si, &out_pi)) {
        Win32_perror("outbash: CreateProcess");
        std::fprintf(stderr, "outbash: CreateProcess failed (%d) for command: %S\n", ::GetLastError(), cmdline.c_str());
        return 1;
    }

    return 0;
}

static int init_winsock()
{
    WSADATA wsaData;
    int iResult;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "outbash: WSAStartup failed: %d\n", iResult);
        return 1;
    }

    return 0;
}

typedef SSIZE_T ssize_t;
ssize_t send_all(const SOCKET sockfd, const void *buffer, const size_t length, const int flags)
{
    if ((ssize_t)length < 0) {
        ::WSASetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }
    const char *cbuf = (const char *)buffer;
    ssize_t rv;
    size_t where;
    bool first = true; // allow a single call to send() if length == 0
    for (where = 0; first || where < length; where += rv) {
        first = false;
        int len = (length - where <= INT_MAX) ? (int)(length - where) : INT_MAX;
        rv = ::send(sockfd, cbuf + where, len, flags);
        if (rv < 0)
            return SOCKET_ERROR;
    }
    assert(where == length);
    return (ssize_t)where;
}

class CUniqueHandle
{
public:
    CUniqueHandle() noexcept : m_handle(NULL) {}
    explicit CUniqueHandle(HANDLE event) noexcept : m_handle(event) {}
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

class CUniqueSocket
{
public:
    explicit CUniqueSocket(SOCKET sock) noexcept : m_socket(sock) {} // adopt existing socket
    CUniqueSocket(int af, int type, int protocol) // create new non-overlapping socket
    {
        m_socket = ::WSASocket(af, type, protocol, NULL, 0, 0);
        if (m_socket == INVALID_SOCKET)
            throw_last_error("WSASocket");
    }
    CUniqueSocket(const CUniqueSocket&) = delete;
    CUniqueSocket& operator =(const CUniqueSocket&) = delete;
    CUniqueSocket(CUniqueSocket&& other) noexcept : m_socket(other.m_socket) { other.m_socket = INVALID_SOCKET; }
    CUniqueSocket& operator =(CUniqueSocket&& other) noexcept
    {
        if (&other != this) {
            close();
            m_socket = other.m_socket;
            other.m_socket = INVALID_SOCKET;
        }
        return *this;
    }
    ~CUniqueSocket() noexcept { close(); }

    SOCKET get() const noexcept { return m_socket; }

    SOCKET release() noexcept { SOCKET ret = m_socket; m_socket = INVALID_SOCKET; return ret; }

    CUniqueHandle create_auto_event(long net_evts)
    {
        HANDLE ev = ::CreateEvent(NULL, FALSE, FALSE, NULL);
        if (ev == NULL) throw_last_error("CreateEvent");
        if (SOCKET_ERROR == ::WSAEventSelect(m_socket, ev, net_evts)) {
            DWORD syserr = ::GetLastError();
            ::CloseHandle(ev);
            throw_system_error("WSAEventSelect (create_auto_event)", syserr);
        }
        return CUniqueHandle(ev);
    }

    CUniqueHandle create_manual_event(long net_evts)
    {
        HANDLE ev = ::WSACreateEvent();
        if (ev == WSA_INVALID_EVENT) throw_last_error("WSACreateEvent");
        if (SOCKET_ERROR == ::WSAEventSelect(m_socket, ev, net_evts)) {
            DWORD syserr = ::GetLastError();
            ::CloseHandle(ev);
            throw_system_error("WSAEventSelect (create_manual_event)", syserr);
        }
        return CUniqueHandle(ev);
    }

    void change_event_select(CUniqueHandle& ev, long net_evts)
    {
        if (SOCKET_ERROR == ::WSAEventSelect(m_socket, ev.get_unchecked(), net_evts))
            throw_last_error("WSAEventSelect (change_event_select)");
    }

    static void set_to_blocking(SOCKET s)
    {
        if (s != INVALID_SOCKET) {
            ::WSAEventSelect(s, NULL, 0);
            unsigned long nonblocking = 0;
            if (::ioctlsocket(s, FIONBIO, &nonblocking) != 0) throw_last_error("set socket to blocking");
        }
    }

    void set_to_blocking()
    {
        set_to_blocking(m_socket);
    }

    void close() noexcept
    {
        if (m_socket != INVALID_SOCKET) {
            ::closesocket(m_socket);
            m_socket = INVALID_SOCKET;
        }
    }

    void shutdown_close() noexcept
    {
        if (m_socket != INVALID_SOCKET) {
            ::shutdown(m_socket, SD_BOTH);
            ::closesocket(m_socket);
            m_socket = INVALID_SOCKET;
        }
    }

private:
    SOCKET    m_socket;
};

class OutbashStdRedirects : public StdRedirects
{
public:
    enum { STDH_INHERIT = 0, STDH_NULL = -1 }; // positive number: TCP port to redirect to

    OutbashStdRedirects() : StdRedirects(), m_redirects(), m_redir_connect_events(), m_same_out_err_socket(false) {}

    void parse_redir_param(role_e role, const char* param)
    {
        if (!std::strcmp(param, "nul")) {
            m_redirects.at(role) = STDH_NULL;
        } else if (!std::strncmp(param, "redirect=", std::strlen("redirect="))) {
            param += std::strlen("redirect=");
            long port = std::atol(param);
            if (port < 1 || port > 65535)
                throw std::runtime_error("redirect wanted to invalid port");
            m_redirects.at(role) = (int)port;
        } else {
            throw std::runtime_error("unrecognized redirect wanted");
        }
    }

    // caller_addr: in network order
    void initiate_connections(uint32_t caller_addr)
    {
        if (m_redirects[REDIR_STDIN] > 0
            && (   m_redirects[REDIR_STDIN] == m_redirects[REDIR_STDOUT]
                || m_redirects[REDIR_STDIN] == m_redirects[REDIR_STDERR]))
            throw std::runtime_error("same redirection wanted for stdin and stdout or stderr, this is not allowed");
        m_same_out_err_socket = (m_redirects[REDIR_STDOUT] > 0)
                                && (m_redirects[REDIR_STDOUT] == m_redirects[REDIR_STDERR]);
        for (int i = REDIR_STDIN; i <= REDIR_STDERR; i++) {
            if (m_redirects[i] < 0) {
                set_to_nul((role_e)i);
            } else if (m_redirects[i] > 0) {
                if (i == REDIR_STDERR && m_same_out_err_socket) {
                    set_same_as_other(REDIR_STDERR, REDIR_STDOUT);
                } else {
                    CUniqueSocket sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                    CUniqueHandle conn_ev = sock.create_auto_event(FD_CONNECT);
                    struct sockaddr_in redir_addr;
                    std::memset(&redir_addr, 0, sizeof(redir_addr));
                    redir_addr.sin_family = AF_INET;
                    redir_addr.sin_addr.s_addr = caller_addr;
                    redir_addr.sin_port = htons((unsigned short)m_redirects[i]);
                    int res = ::connect(sock.get(), (const struct sockaddr *)&redir_addr, sizeof(redir_addr));
                    if (res == SOCKET_ERROR && ::GetLastError() != WSAEWOULDBLOCK) throw_last_error("connect");
                    else if (res == SOCKET_ERROR) { // ::GetLastError() == WSAEWOULDBLOCK
                        adopt_handle((role_e)i, (HANDLE)sock.release());
                        m_redir_connect_events.at(i) = std::move(conn_ev);
                    } else {
                        conn_ev.close();
                        // ::shutdown(sock.get(), i == REDIR_STDIN ? SD_SEND : SD_RECEIVE);
                        sock.set_to_blocking();
                        adopt_handle((role_e)i, (HANDLE)sock.release());
                    }
                }
            }
        }
    }

    // Complete connections to redirection sockets before the controlling socket
    // closes (too early), or throw an exception.
    void complete_connections(CUniqueHandle& ctrl_close_ev)
    {
        std::array<HANDLE, 4> wait_handles;
        while (1)
        {
            unsigned int nb = 0;
            for (const auto& ev: m_redir_connect_events) {
                if (ev.is_valid()) {
                    wait_handles.at(nb + 1) = ev.get_unchecked();
                    nb++;
                }
            }
            if (!nb)
                break;

            wait_handles.at(0) = ctrl_close_ev.get_checked();
            nb++;

            DWORD wr = ::WaitForMultipleObjects(nb, &wait_handles[0], FALSE, INFINITE);
            if (wr == WAIT_FAILED) throw_last_error("WaitForMultipleObjects (complete_connections)");
            if (wr == WAIT_OBJECT_0) throw std::runtime_error("Control socket closed while trying to connect redirection sockets");
            // XXX we should check that we really connected
            unsigned i = idx_from_evhandle(wait_handles.at(wr - WAIT_OBJECT_0));
            m_redir_connect_events.at(i).close();
            SOCKET s_i = (SOCKET)get_handle((role_e)i);
            // ::shutdown(s_i, i == REDIR_STDIN ? SD_SEND : SD_RECEIVE);
            CUniqueSocket::set_to_blocking(s_i);
        }
    }
private:
    unsigned int idx_from_evhandle(HANDLE ev)
    {
        for (unsigned int i = 0; i < m_redir_connect_events.size(); i++) {
            if (m_redir_connect_events[i].get_unchecked() == ev)
                return i;
        }
        throw std::logic_error("event handle not found");
    }
private:
    std::array<int, 3>              m_redirects;
    std::array<CUniqueHandle, 3>     m_redir_connect_events;
    bool                            m_same_out_err_socket;
};

class CConnection
{
public:
    explicit CConnection(CUniqueSocket&& usock) noexcept : m_usock(std::move(usock)) {}

    void run()
    {
        try {
            CActiveConnection _con(m_usock);
            _con.run();
        } catch (const std::exception& e) {
            std::fprintf(stderr, "outbash: CConnection::run() exception: %s\n", e.what());
        }
        m_usock.close();
    }

private:
    class CActiveConnection
    {
    public:
        explicit CActiveConnection(CUniqueSocket& usock) noexcept : m_usock(usock), m_buf() {}

        bool buf_get_line(std::string& out_line)
        {
            out_line.clear();

            if (m_buf.size() > line_supported_length)
                throw std::runtime_error("line too long received from peer");

            char* nlptr = (char*)std::memchr(&m_buf[0], '\n', m_buf.size());
            if (nlptr) {
                int pos = (int)(nlptr - &m_buf[0]);
                out_line.append(&m_buf[0], pos);
                if (!out_line.empty() && out_line.back() == '\r')
                    out_line.pop_back();
                m_buf.replace(0, pos + 1, "");
                return true;
            }

            return false;
        }

        int buf_recv()
        {
            size_t buf_orig_size = m_buf.size();

            m_buf.resize(buf_orig_size + ctrl_recv_block_size);
            int res = ::recv(m_usock.get(), &m_buf[buf_orig_size], ctrl_recv_block_size, 0);
            if (res < 0) {
                DWORD err = GetLastError();
                m_buf.resize(buf_orig_size);
                SetLastError(err);
                return res;
            }
            m_buf.resize(buf_orig_size + res);
            return res;
        }

        std::string recv_line()
        {
            std::string result;
            while (1) {
                char* nlptr = (char*)std::memchr(&m_buf[0], '\n', m_buf.size());
                if (nlptr) {
                    int pos = (int)(nlptr - &m_buf[0]);
                    result.append(&m_buf[0], pos);
                    if (!result.empty() && result.back() == '\r')
                        result.pop_back();
                    m_buf.replace(0, pos + 1, "");
                    return result;
                } else {
                    result.append(m_buf);
                    m_buf.clear();
                    if (result.size() > line_supported_length)
                        throw std::runtime_error("line too long received from peer");
                }

                assert(m_buf.size() == 0);
                m_buf.resize(ctrl_recv_block_size);
                int res = ::recv(m_usock.get(), &m_buf[0], (int)m_buf.size(), 0);

                if (res < 0) {
                    Win32_perror("outbash: recv");
                    m_buf.clear();
                    throw std::runtime_error("recv() returned an error");
                }

                m_buf.resize(res);

                if (res == 0)
                    throw std::runtime_error("a connection closed too early");

                if (std::memchr(&m_buf[0], 0, m_buf.size()))
                    throw std::runtime_error("nul byte received from peer");
            }
        }

        void run()
        {
            CUniqueHandle process_handle;
            std::unique_ptr<OutbashStdRedirects> redir(nullptr);
            CUniqueHandle ctrl_ev;

            // scope for locals lifetime:
            {
                PROCESS_INFORMATION pi;
                std::wstring wrun;
                std::wstring wcd;
                std::unique_ptr<EnvVars> vars(nullptr);
                auto vars_cp = [&] { if (!vars) vars.reset(new EnvVars(initial_env_vars)); return vars.get(); };
                auto inst_redir = [&] { if (!redir) redir.reset(new OutbashStdRedirects); return redir.get(); };

                while (1) {
                    std::string line = recv_line();

                    if (line == "")
                        break;
                    else if (startswith(line, "run:"))
                        wrun = utf::widen(&line[4]);
                    else if (startswith(line, "cd:"))
                        wcd = utf::widen(&line[3]);
                    else if (startswith(line, "env:"))
                        vars_cp()->set_from_utf8(&line[4]);
                    else if (startswith(line, "stdin:"))
                        inst_redir()->parse_redir_param(StdRedirects::REDIR_STDIN, &line[6]);
                    else if (startswith(line, "stdout:"))
                        inst_redir()->parse_redir_param(StdRedirects::REDIR_STDOUT, &line[7]);
                    else if (startswith(line, "stderr:"))
                        inst_redir()->parse_redir_param(StdRedirects::REDIR_STDERR, &line[7]);
                }

                ctrl_ev = m_usock.create_manual_event(FD_CLOSE);

                if (redir.get()) {
                    struct sockaddr_in caller_addr;
                    int namelen = sizeof(caller_addr);
                    if (::getpeername(m_usock.get(), (sockaddr *)&caller_addr, &namelen) != 0) {
                        Win32_perror("outbash: getsockname (caller)");
                        caller_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // fallback
                    }
                    redir.get()->initiate_connections(caller_addr.sin_addr.s_addr);
                    redir.get()->complete_connections(ctrl_ev);
                }

                if (start_command(wrun, wcd.c_str(), vars.get(), redir.get(), pi) != 0)
                    return;

                ::CloseHandle(pi.hThread);
                process_handle = CUniqueHandle(pi.hProcess);
            }

            m_usock.change_event_select(ctrl_ev, FD_CLOSE | FD_READ);

            bool try_get_line = true;
            bool ctrl_socket_failed = false;
            DWORD wr;
            do {
                const bool ctrl_socket_was_ok = !ctrl_socket_failed;

                HANDLE wait_handles[2] = { ctrl_ev.get_checked(), process_handle.get_checked() };
                wr = ::WaitForMultipleObjects(2, &wait_handles[0], FALSE, try_get_line ? 0 : INFINITE);

                if (wr == WAIT_FAILED)
                    throw_last_error("WaitForMultipleObjects (run)"); // XXX not ideal

                if (wr == WAIT_OBJECT_0) {
                    WSANETWORKEVENTS ctrl_network_events;
                    if (SOCKET_ERROR == ::WSAEnumNetworkEvents(m_usock.get(), wait_handles[0], &ctrl_network_events))
                        throw_last_error("WSAEnumNetworkEvents"); // XXX not ideal

                    if (ctrl_network_events.lNetworkEvents & FD_CLOSE)
                        ctrl_socket_failed = true;

                    // if FD_READ, try_get_line will eventually be false
                    // (if not yet ctrl_socket_failed), and ::recv in buf_recv
                    // will re-enable FD_READ
                }

                if (try_get_line && !ctrl_socket_failed) {
                    std::string line;
                    try {
                        try_get_line = buf_get_line(line);
                    } catch (const std::runtime_error& e) {
                        try_get_line = false;
                        ctrl_socket_failed = true;
                        std::fprintf(stderr, "\noutbash: buf_get_line() exception: %s\n", e.what());
                    }

                    if (try_get_line) {
                        // XXX: be mad about nul bytes?
                        if (line == "suspend")
                            std::fprintf(stderr, "\noutbash: XXX suspend\n");
                        else if (line == "resume")
                            std::fprintf(stderr, "\noutbash: XXX resume\n");
                    }
                }

                if (!try_get_line && !ctrl_socket_failed) {
                    int r = buf_recv();
                    if (r < 0) {
                        if (WSAGetLastError() != WSAEWOULDBLOCK)
                            throw_last_error("buf_recv"); // XXX not ideal
                    } else {
                        try_get_line = !!r;
                    }
                }

                if (ctrl_socket_failed) {
                    try_get_line = false;
                    if (ctrl_socket_was_ok) {
                        m_usock.change_event_select(ctrl_ev, FD_CLOSE);
                        ::TerminateProcess(process_handle.get_unchecked(), 0xC0000001);
                    }
                }

            // while process not finished:
            } while (wr != WAIT_OBJECT_0 + 1);

            DWORD exit_code;
            if (!::GetExitCodeProcess(process_handle.get_checked(), &exit_code)) {
                Win32_perror("outbash: GetExitCodeProcess");
                exit_code = (DWORD)-1;
            }
            process_handle.close();

            if (redir.get())
                redir.get()->close();

            ctrl_ev.close();

            if (!ctrl_socket_failed) {
                m_usock.set_to_blocking();
                char buf_rc[16]; (void)std::snprintf(buf_rc, 16, "%u\n", (unsigned int)exit_code);
                send_all(m_usock.get(), buf_rc, std::strlen(buf_rc), 0);
                m_usock.shutdown_close();
            } else {
                std::fprintf(stderr, "\noutbash: Control socket failed: process killed.\n");
            }
        }

    private:
        const size_t line_supported_length = 32768*3 + 16; // in bytes (UTF-8); indicative approx max length (the size can grow to at least that)
        const int ctrl_recv_block_size = 8192;
        CUniqueSocket&  m_usock;
        std::string     m_buf;
    };

private:
    CUniqueSocket   m_usock;
};

// return temporary filename (in UTF-8)
static std::string get_temp_filename(DWORD unique)
{
    #define TMP_BUFLEN (MAX_PATH+2)
    wchar_t w_temp_path[TMP_BUFLEN];
    DWORD res = ::GetTempPathW(TMP_BUFLEN, w_temp_path);
    if (res == 0) { Win32_perror("outbash: GetTempPath"); std::exit(EXIT_FAILURE); }
    return utf::narrow(w_temp_path) + "outbash." + std::to_string((unsigned int)unique);
}

// convert Win32 filename to WSL filename (both in UTF-8)
static std::string convert_to_wsl_filename(const std::string& win32_filename)
{
    if (win32_filename.length() <= 3
        || !is_ascii_letter(win32_filename[0])
        || win32_filename[1] != ':'
        || win32_filename[2] != '\\') {
        std::fprintf(stderr, "outbash: Unable to convert filename to WSL: %s\n", win32_filename.c_str());
        std::exit(EXIT_FAILURE);
    }
    std::string result = "/mnt/";
    result += to_ascii_lower(win32_filename[0]);
    result += '/';
    result += &win32_filename[3];
    std::replace(result.begin(), result.end(), '\\', '/');
    return result;
}

struct ThreadConnection {
    std::unique_ptr<CConnection>    m_pConn;
    std::thread                     m_thread;
};

static void reap_connections(std::vector<ThreadConnection>& vTConn)
{
    std::vector<ThreadConnection> remain_conns;

    for (auto& tc : vTConn) {
        HANDLE tHdl = (HANDLE)tc.m_thread.native_handle();
        DWORD exit_code;
        if (::GetExitCodeThread(tHdl, &exit_code) == 0) {
            Win32_perror("outbash: GetExitCodeThread");
            // what can we do? I guess leaking is not so bad in that case
            tc.m_thread.detach();
            tc.m_pConn.release();
            continue;
        }
        if (exit_code == STILL_ACTIVE) {
            remain_conns.push_back(std::move(tc));
        } else {
            tc.m_thread.join();
        }
    }

    std::swap(vTConn, remain_conns);
}

static void init_locale_console_cp()
{
    UINT cp = ::GetConsoleOutputCP();
    char buf[16];
    (void)std::snprintf(buf, 16, ".%u", cp);
    buf[15] = 0;
    std::setlocale(LC_ALL, buf);
    _setmbcp((int)cp);
}

int main()
{
    init_locale_console_cp();
    if (init_winsock() != 0) std::exit(EXIT_FAILURE);

    CUniqueSocket sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    struct sockaddr_in serv_addr;
    std::memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serv_addr.sin_port = 0;
    if (::bind(sock.get(), (const sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) { Win32_perror("outbash: bind"); std::exit(EXIT_FAILURE); }
    int namelen = sizeof(serv_addr);
    if (::getsockname(sock.get(), (sockaddr *)&serv_addr, &namelen) != 0) { Win32_perror("outbash: getsockname"); std::exit(EXIT_FAILURE); }

    if (::listen(sock.get(), SOMAXCONN_HINT(600)) != 0) { Win32_perror("outbash: listen"); std::exit(EXIT_FAILURE); }

    CUniqueHandle accept_event = sock.create_auto_event(FD_ACCEPT);

    std::string tmp_filename = get_temp_filename(GetCurrentProcessId());
    std::string wsl_tmp_filename = convert_to_wsl_filename(tmp_filename);
    std::FILE *f = _wfopen(utf::widen(tmp_filename).c_str(), L"wb");
    if (!f) { std::fprintf(stderr, "outbash: could not open temporary file %S\n", utf::widen(tmp_filename).c_str()); std::exit(EXIT_FAILURE); }
    std::fprintf(f, "export OUTBASH_PORT=%u\n", (unsigned)ntohs(serv_addr.sin_port));
    std::fprintf(f, ". /etc/bash.bashrc\n");
    std::fprintf(f, ". ~/.bashrc\n");
    std::fclose(f);
    // XXX check fprintf/fclose errors

    PROCESS_INFORMATION pi;
    if (start_command(
            utf::widen("bash --rcfile \"" + wsl_tmp_filename + "\" ") + get_cmd_line_params(),
            nullptr, nullptr, nullptr,
            pi) != 0) {
        _wremove(utf::widen(tmp_filename).c_str());
        std::exit(EXIT_FAILURE);
    }
    ::CloseHandle(pi.hThread);

    std::vector<ThreadConnection> vTConn;

    while (1) {
        HANDLE wait_handles[2] = { pi.hProcess, accept_event.get_unchecked() };
        DWORD timeout = vTConn.empty() ? INFINITE : 5000;
        DWORD wr = ::WaitForMultipleObjects(accept_event.is_valid() ? 2 : 1, wait_handles, FALSE, timeout);
        if (wr == WAIT_FAILED) {
            Win32_perror("outbash: WaitForMultipleObjects");
            std::quick_exit(EXIT_FAILURE);
        }

        reap_connections(vTConn);

        switch (wr) {
        case WAIT_TIMEOUT:
            /* nothing to do, it was just for reap_connections() */
            break;
        case WAIT_OBJECT_0 + 1:
            {
                struct sockaddr_in conn_addr;
                int conn_addr_len = (int)sizeof(conn_addr);
                SOCKET conn = ::accept(sock.get(), (struct sockaddr*)&conn_addr, &conn_addr_len);
                if (conn == INVALID_SOCKET) {
                    switch (::WSAGetLastError()) {
                    case WSAECONNRESET:
                    case WSAEINPROGRESS:
                    case WSAEWOULDBLOCK:
                        break;
                    case WSAENOBUFS:
                    case WSAEMFILE:
                        // there is not much we can do, except notifying the user and
                        // hoping things will get better later
                        Win32_perror("outbash: accept");
                        break;
                    case WSAENETDOWN:
                        // this is really bad, but we will try to continue to wait for bash to terminate
                        Win32_perror("outbash: accept");
                        accept_event.close();
                        sock.close();
                        break;
                    default:
                        Win32_perror("outbash: accept");
                        std::quick_exit(EXIT_FAILURE);
                    }
                } else {
                    CUniqueSocket usock(conn);
                    try {
                        usock.set_to_blocking();
                        ThreadConnection tc{ std::make_unique<CConnection>(std::move(usock)), std::thread() };
                        CConnection *pConnection = tc.m_pConn.get();
                        tc.m_thread = std::thread([=] { pConnection->run(); });
                        vTConn.push_back(std::move(tc));
                    } catch (const std::system_error& e) {
                        std::fprintf(stderr, "outbash: exception system_error when trying to handle a new request: %s\n", e.what());
                    }
                }
                break;
            }
        case WAIT_OBJECT_0:
            ::CloseHandle(pi.hProcess);
            _wremove(utf::widen(tmp_filename).c_str());
            std::quick_exit(EXIT_SUCCESS);
            break;
        }
    }
}
