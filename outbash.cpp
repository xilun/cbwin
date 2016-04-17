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
#include <cstdio>
#include <cstdlib>
#include <cstring>

#pragma comment(lib, "Ws2_32.lib")

int start_command(const char* command, PROCESS_INFORMATION& pi)
{
    STARTUPINFO si;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    std::string cmd(command);
    if (!::CreateProcessA(NULL, &cmd[0], NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi)) {
        std::fprintf(stderr, "CreateProcess failed (%d) for command: %s\n", GetLastError(), command);
        return 1;
    }

    return 0;
}

void Win32_perror(const char* what)
{
    const int errnum = GetLastError();
    const bool what_present = (what && *what);

    // Getting a proper output in the console _and_ not breaking everything
    // else is a complete and utter mess.
    // By default we have a raster font at least for latin based localized
    // systems, that means SetConsoleOutputCP() will do nothing.
    // fwprintf() targets the current mbcp, which is ANSI and not OEM.
    // We can not just call _setmbcp(), that would have a process wide effect.
    // A direct call to WriteConsoleW works, but won't be redirected...
    // So the "good" solution is to convert to the console mbcs and use fprintf.
    // Only tested on a French install, but I guess that should work properly
    // everywhere.
    // Obviously when you redirect you get "garbage" (OEM chars from the 90s
    // in a file you will probably never read with that encoding) but that is
    // what you also get with MS programs, so at least it is consistent "garbage."

    WCHAR *str;
    DWORD nbWChars = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER
                                    | FORMAT_MESSAGE_FROM_SYSTEM
                                    | FORMAT_MESSAGE_IGNORE_INSERTS
                                    | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                                    nullptr, (DWORD)errnum, 0, (LPWSTR)&str,
                                    0, nullptr);
    if (nbWChars == 0) {
        fprintf(stderr, "%s%ssocket error %d (FormatMessage failed)\n",
                what_present ? what : "",
                what_present ? ": " : "",
                errnum);
    } else {
        // Worst case would be 4 bytes per character for UTF-8
        const int mbstr_bufsz = (int)nbWChars * 4 + 1;
        std::unique_ptr<char[]> mbstr(new char[mbstr_bufsz]);
        WideCharToMultiByte(GetConsoleOutputCP(), 0, str, nbWChars + 1,
                            mbstr.get(), mbstr_bufsz, nullptr, nullptr);
        fprintf(stderr, "%s%s%s\n",
                what_present ? what : "",
                what_present ? ": " : "",
                mbstr.get());
        LocalFree(str);
    }
    SetLastError(errnum);
}

int init_winsock()
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

class CConnection {
public:
    CConnection(SOCKET conn_sock) : m_conn_sock(conn_sock) {}
    CConnection(const CConnection&) = delete;
    CConnection& operator =(const CConnection&) = delete;
    ~CConnection() { close_sock(); }

    void run()
    {
        char command[32769];
        memset(command, 0, sizeof(command));
        int where = 0;

        do {
            int max_read = (int)sizeof(command) - 1 - where;
            if (max_read < 1) {
                std::fprintf(stderr, "recv: command too long\n");
                close_sock();
                return;
            }

            int res = recv(m_conn_sock, command + where, max_read, 0);

            if (res < 0) {
                Win32_perror("recv");
                close_sock();
                return;
            }
            if (res == 0) {
                std::fprintf(stderr, "recv: connection closed\n");
                close_sock();
                return;
            }

            where += res;

        } while (memchr(command, 0, where) == nullptr && memchr(command, '\n', where) == nullptr);

        /* there must be a single \n, right at the end */
        char *lf = strchr(command, '\n');
        if (!lf || lf - command != (int)strlen(command) - 1) {
            std::fprintf(stderr, "CConnection::run: invalid command terminating character\n");
            close_sock();
            return;
        }

        *lf = '\0';
        if (lf != command && lf[-1] == '\r')
            lf[-1] = '\0';

        PROCESS_INFORMATION pi;
        if (start_command(command, pi) != 0) {
            close_sock();
            return;
        }

        ::WaitForSingleObject(pi.hProcess, INFINITE);
        ::CloseHandle(pi.hProcess);
        ::CloseHandle(pi.hThread);

        close_sock();
    }

private:
    void close_sock()
    {
        if (m_conn_sock != INVALID_SOCKET) {
            ::shutdown(m_conn_sock, SD_BOTH);
            ::closesocket(m_conn_sock);
            m_conn_sock = INVALID_SOCKET;
        }
    }

private:
    SOCKET    m_conn_sock;
};

std::string get_temp_filename(DWORD unique)
{
    #define TMP_BUFLEN (280)    // > Win32 MAX_PATH
    char buffer_path_name[TMP_BUFLEN];
    DWORD res = GetTempPathA(TMP_BUFLEN, buffer_path_name);
    if (res == 0) { Win32_perror("GetTempPath"); std::exit(EXIT_FAILURE); }
    std::snprintf(buffer_path_name + res, TMP_BUFLEN - res, "outbash.%u", (unsigned int)unique);
    return buffer_path_name;
}

bool is_ascii_letter(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

char to_ascii_lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c;
}

std::string convert_to_wsl_filename(const std::string& win32_filename)
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

int main()
{
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

    if (::listen(sock, 50) != 0) { Win32_perror("listen"); std::exit(EXIT_FAILURE); }

    WSAEVENT accept_event = ::CreateEvent(NULL, FALSE, FALSE, NULL);
    ::WSAEventSelect(sock, accept_event, FD_ACCEPT);

    std::string tmp_filename = get_temp_filename(GetCurrentProcessId());
    std::string wsl_tmp_filename = convert_to_wsl_filename(tmp_filename);
    std::FILE *f = std::fopen(tmp_filename.c_str(), "wb");
    if (!f) { std::fprintf(stderr, "could not open temporary file %s\n", tmp_filename.c_str()); std::exit(EXIT_FAILURE); }
    std::fprintf(f, "export OUTBASH_PORT=%u\n", (unsigned)ntohs(serv_addr.sin_port));
    std::fprintf(f, ". /etc/bash.bashrc\n");
    std::fprintf(f, ". ~/.bashrc\n");
    std::fclose(f);

    PROCESS_INFORMATION pi;
    if (start_command(("bash --rcfile " + wsl_tmp_filename).c_str(), pi) != 0) { std::remove(tmp_filename.c_str()); std::exit(EXIT_FAILURE); }

    struct ThreadConnection {
        std::unique_ptr<CConnection>    m_pConn;
        std::thread                     m_thread;
    };
    std::vector<ThreadConnection> vTConn;

    while (1) {
        HANDLE wait_handles[2] = { accept_event, pi.hProcess };
        DWORD wr = ::WaitForMultipleObjects(2, wait_handles, FALSE, INFINITE);
        switch (wr) {
        case WAIT_OBJECT_0:
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
                    default:
                        Win32_perror("accept");
                        std::quick_exit(EXIT_FAILURE);
                    }
                } else {
                    // Winsock is designed by monkeys:
                    ::WSAEventSelect(conn, NULL, 0);
                    unsigned long nonblocking = 0;
                    if (::ioctlsocket(conn, FIONBIO, &nonblocking) != 0) {
                        Win32_perror("set socket to non-blocking");
                    } else {
                        ThreadConnection tc{ std::make_unique<CConnection>(conn), std::thread() };
                        CConnection *pConnection = tc.m_pConn.get();
                        tc.m_thread = std::thread([=] { pConnection->run(); });
                        vTConn.push_back(std::move(tc));
                    }
                }
                break;
            }
        case WAIT_OBJECT_0 + 1:
            ::CloseHandle(pi.hProcess);
            ::CloseHandle(pi.hThread);
            std::remove(tmp_filename.c_str());
            std::quick_exit(EXIT_SUCCESS);
            break;
        case WAIT_FAILED:
            Win32_perror("WaitForMultipleObjects");
            std::quick_exit(EXIT_FAILURE);
            break;
        }
    }
}
