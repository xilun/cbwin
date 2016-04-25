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

#pragma comment(lib, "Ws2_32.lib")

using std::size_t;
using std::uint16_t;

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
    UINT res = GetEnvironmentVariableW(L"ComSpec", buf, MAX_PATH+1);
    if (res == 0 && GetLastError() == ERROR_ENVVAR_NOT_FOUND) {
        res = GetSystemDirectoryW(buf, MAX_PATH+1);
        if (res == 0 || res > MAX_PATH) { std::fprintf(stderr, "GetSystemDirectory error\n"); std::abort(); }
        return buf + std::wstring(L"\\cmd.exe");
    } else {
        if (res == 0 || res > MAX_PATH) { std::fprintf(stderr, "GetEnvironmentVariable ComSpec error\n"); std::abort(); }
        return buf;
    }
}
static const std::wstring comspec = get_comspec();

static void Win32_perror(const char* what)
{
    const int errnum = GetLastError();
    const bool what_present = (what && *what);

    WCHAR *str;
    DWORD nbWChars = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER
                                    | FORMAT_MESSAGE_FROM_SYSTEM
                                    | FORMAT_MESSAGE_IGNORE_INSERTS
                                    | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                                    nullptr, (DWORD)errnum, 0, (LPWSTR)&str,
                                    0, nullptr);
    if (nbWChars == 0) {
        fprintf(stderr, "%s%swin32 error %d (FormatMessage failed)\n",
                what_present ? what : "",
                what_present ? ": " : "",
                errnum);
    } else {
        fprintf(stderr, "%s%s%S\n",
                what_present ? what : "",
                what_present ? ": " : "",
                str);
        LocalFree(str);
    }
    SetLastError(errnum);
}

int wstr_case_ascii_ncmp(const wchar_t* s1, const wchar_t* s2, size_t n)
{
    wchar_t c1, c2;
    do {
        c1 = *s1++;
        c2 = *s2++;
        if (n == 0)
            c1 = L'\0';
        n--;
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

static int start_command(std::wstring cmdline, const wchar_t* dir, PROCESS_INFORMATION& out_pi)
{
    STARTUPINFOW si;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&out_pi, sizeof(out_pi));

    const wchar_t* wdir = nullptr;
    if (dir != nullptr && *dir != L'\0') {
        // CreateProcess will happily use a relative, but we don't want to
        if (!path_is_really_absolute(dir)) {
            std::fprintf(stderr, "start_command: non-absolute directory parameter: %S\n", dir);
            return 1;
        }
        wdir = dir;
    }

    const wchar_t* module = NULL;
    if (wstr_case_ascii_ncmp(cmdline.c_str(), L"cmd", 3) == 0 && is_cmd_line_sep(cmdline[3]))
        module = comspec.c_str();

    if (!::CreateProcessW(module, &cmdline[0], NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT, NULL, wdir, &si, &out_pi)) {
        Win32_perror("CreateProcess");
        std::fprintf(stderr, "CreateProcess failed (%d) for command: %S\n", GetLastError(), cmdline.c_str());
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
        fprintf(stderr, "WSAStartup failed: %d\n", iResult);
        return 1;
    }

    return 0;
}

class CUniqueSocket {
public:
    explicit CUniqueSocket(SOCKET conn_sock) noexcept : m_socket(conn_sock) {}
    CUniqueSocket(const CUniqueSocket&) = delete;
    CUniqueSocket& operator =(const CUniqueSocket&) = delete;
    CUniqueSocket(CUniqueSocket&& other) noexcept : m_socket(other.m_socket) { other.m_socket = INVALID_SOCKET; }
    CUniqueSocket& operator =(CUniqueSocket&& other) noexcept
    {
        if (&other != this)
        {
            abrupt_close();
            m_socket = other.m_socket;
            other.m_socket = INVALID_SOCKET;
        }
        return *this;
    }
    ~CUniqueSocket() noexcept { abrupt_close(); }

    SOCKET get() const noexcept { return m_socket; }

    void abrupt_close() noexcept
    {
        if (m_socket != INVALID_SOCKET) {
            ::closesocket(m_socket);
            m_socket = INVALID_SOCKET;
        }
    }

    void graceful_close() noexcept
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

class CConnection {
public:
    explicit CConnection(CUniqueSocket&& usock) noexcept : m_usock(std::move(usock)) {}

    void run()
    {
        try {
            CActiveConnection _con(m_usock);
            _con.run();
        } catch (const std::exception& e) {
            std::fprintf(stderr, "CConnection::run() exception: %s\n", e.what());
        }
        m_usock.abrupt_close();
    }

private:
    class CActiveConnection {
    public:
        explicit CActiveConnection(CUniqueSocket& usock) noexcept : m_usock(usock), m_buf() {}

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
                m_buf.resize(8192);
                int res = ::recv(m_usock.get(), &m_buf[0], (int)m_buf.size(), 0);

                if (res < 0) {
                    Win32_perror("recv");
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
            std::string line;
            std::string run;
            std::string cd;

            while (1) {
                line = recv_line();

                if (line == "")
                    break;
                else if (startswith(line, "run:"))
                    run = std::move(line);
                else if (startswith(line, "cd:"))
                    cd = std::move(line);
            }
            std::wstring wcd = !cd.empty() ? utf::widen(&cd[3]) : std::wstring();
            std::wstring wrun = !run.empty() ? utf::widen(&run[4]) : std::wstring();

            PROCESS_INFORMATION pi;
            if (start_command(wrun, wcd.c_str(), pi) != 0)
                return;

            ::CloseHandle(pi.hThread);
            ::WaitForSingleObject(pi.hProcess, INFINITE);
            ::CloseHandle(pi.hProcess);

            m_usock.graceful_close();
        }

    private:
        const size_t line_supported_length = 32768*3 + 16; // in bytes (UTF-8); indicative approx max length (the size can grow to at least that)
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
    DWORD res = GetTempPathW(TMP_BUFLEN, w_temp_path);
    if (res == 0) { Win32_perror("GetTempPath"); std::exit(EXIT_FAILURE); }
    return utf::narrow(w_temp_path) + "outbash." + std::to_string((unsigned int)unique);
}

// convert Win32 filename to WSL filename (both in UTF-8)
static std::string convert_to_wsl_filename(const std::string& win32_filename)
{
    if (win32_filename.length() <= 3
        || !is_ascii_letter(win32_filename[0])
        || win32_filename[1] != ':'
        || win32_filename[2] != '\\') {
        std::fprintf(stderr, "Unable to convert filename to WSL: %s\n", win32_filename.c_str());
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
        if (GetExitCodeThread(tHdl, &exit_code) == 0) {
            Win32_perror("GetExitCodeThread");
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
    UINT cp = GetConsoleOutputCP();
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

    SOCKET sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) { Win32_perror("socket"); std::exit(EXIT_FAILURE); }

    struct sockaddr_in serv_addr;
    std::memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serv_addr.sin_port = 0;
    if (::bind(sock, (const sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) { Win32_perror("bind"); std::exit(EXIT_FAILURE); }
    int namelen = sizeof(serv_addr);
    if (::getsockname(sock, (sockaddr *)&serv_addr, &namelen) != 0) { Win32_perror("getsockname"); std::exit(EXIT_FAILURE); }

    if (::listen(sock, SOMAXCONN_HINT(600)) != 0) { Win32_perror("listen"); std::exit(EXIT_FAILURE); }

    WSAEVENT accept_event = ::CreateEvent(NULL, FALSE, FALSE, NULL);
    if (accept_event == NULL) { Win32_perror("CreateEvent"); std::exit(EXIT_FAILURE); }
    ::WSAEventSelect(sock, accept_event, FD_ACCEPT);

    std::string tmp_filename = get_temp_filename(GetCurrentProcessId());
    std::string wsl_tmp_filename = convert_to_wsl_filename(tmp_filename);
    std::FILE *f = _wfopen(utf::widen(tmp_filename).c_str(), L"wb");
    if (!f) { std::fprintf(stderr, "could not open temporary file %S\n", utf::widen(tmp_filename).c_str()); std::exit(EXIT_FAILURE); }
    std::fprintf(f, "export OUTBASH_PORT=%u\n", (unsigned)ntohs(serv_addr.sin_port));
    std::fprintf(f, ". /etc/bash.bashrc\n");
    std::fprintf(f, ". ~/.bashrc\n");
    std::fclose(f);
    // XXX check fprintf/fclose errors

    PROCESS_INFORMATION pi;
    if (start_command(
            utf::widen("bash --rcfile \"" + wsl_tmp_filename + "\" ") + get_cmd_line_params(),
            nullptr,
            pi) != 0) {
        _wremove(utf::widen(tmp_filename).c_str());
        std::exit(EXIT_FAILURE);
    }
    ::CloseHandle(pi.hThread);

    std::vector<ThreadConnection> vTConn;

    bool network_ok = true;
    while (1) {
        HANDLE wait_handles[2] = { pi.hProcess, accept_event };
        DWORD timeout = vTConn.empty() ? INFINITE : 5000;
        DWORD wr = ::WaitForMultipleObjects(network_ok ? 2 : 1, wait_handles, FALSE, timeout);
        if (wr == WAIT_FAILED) {
            Win32_perror("WaitForMultipleObjects");
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
                SOCKET conn = ::accept(sock, (struct sockaddr*)&conn_addr, &conn_addr_len);
                if (conn == INVALID_SOCKET) {
                    switch (WSAGetLastError()) {
                    case WSAECONNRESET:
                    case WSAEINPROGRESS:
                    case WSAEWOULDBLOCK:
                        break;
                    case WSAENOBUFS:
                    case WSAEMFILE:
                        // there is not much we can do, except notifying the user and
                        // hoping things will get better later
                        Win32_perror("accept");
                        break;
                    case WSAENETDOWN:
                        // this is really bad, but we will try to continue to wait for bash to terminate
                        Win32_perror("accept");
                        network_ok = false;
                        ::closesocket(sock);
                        sock = INVALID_SOCKET;
                        ::CloseHandle(accept_event);
                        accept_event = INVALID_HANDLE_VALUE;
                        break;
                    default:
                        Win32_perror("accept");
                        std::quick_exit(EXIT_FAILURE);
                    }
                } else {
                    CUniqueSocket usock(conn);
                    // Winsock is designed by monkeys:
                    ::WSAEventSelect(usock.get(), NULL, 0);
                    unsigned long nonblocking = 0;
                    if (::ioctlsocket(usock.get(), FIONBIO, &nonblocking) != 0) {
                        Win32_perror("set socket to blocking");
                    } else {
                        try {
                            ThreadConnection tc{ std::make_unique<CConnection>(std::move(usock)), std::thread() };
                            CConnection *pConnection = tc.m_pConn.get();
                            tc.m_thread = std::thread([=] { pConnection->run(); });
                            vTConn.push_back(std::move(tc));
                        } catch (const std::system_error& e) {
                            std::fprintf(stderr, "exception system_error when trying to launch new connection thread: %s\n", e.what());
                        }
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
