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

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <Windows.h>

#include <new>
#include <stdexcept>
#include <cstdlib>

#include "tcp_help.h"


#define MY_SIZEOF_TCPTABLE_OWNER_PID(X) ( FIELD_OFFSET(MIB_TCPTABLE_OWNER_PID, table[0])    \
                                          + ((X) * sizeof(MIB_TCPROW_OWNER_PID)) + 8 )

#define MY_ROUNDUP_TCPTABLE_OWNER_PID(bytes)                                                            \
    ( ( ((bytes) + sizeof(MIB_TCPROW_OWNER_PID) - 9 - FIELD_OFFSET(MIB_TCPTABLE_OWNER_PID, table[0]))   \
        / sizeof(MIB_TCPROW_OWNER_PID) * sizeof(MIB_TCPROW_OWNER_PID) )                                 \
      + FIELD_OFFSET(MIB_TCPTABLE_OWNER_PID, table[0]) + 8 )


namespace {


class CTcpPidTable {
    // GetExtendedTcpTable() sometimes fails for unknown reasons and returns 0xc0000001
    // We limit the number of retries to max_ntfail_retries in that case.
    static const int max_ntfail_retries = 5;
public:
    CTcpPidTable()
    {
        DWORD result;
        DWORD table_size = MY_SIZEOF_TCPTABLE_OWNER_PID(64);
        int nt_retries = max_ntfail_retries;
        do {
            m_table = (PMIB_TCPTABLE_OWNER_PID)std::malloc(table_size);
            if (m_table == nullptr)
                throw std::bad_alloc();

            DWORD new_table_size;
            do {
                new_table_size = table_size;
                result = ::GetExtendedTcpTable(m_table, &new_table_size, FALSE, AF_INET,
                                               TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
            } while (result == 0xc0000001 && nt_retries > 0 && nt_retries--);

            if (result != NO_ERROR) {
                std::free(m_table);
                if (result != ERROR_INSUFFICIENT_BUFFER)
                    throw_system_error("GetExtendedTcpTable", result);
                table_size = MY_ROUNDUP_TCPTABLE_OWNER_PID(table_size + (table_size >> 3));
                if (new_table_size > table_size)
                    table_size = new_table_size;
            }
        } while (result != NO_ERROR);
    }
    CTcpPidTable(CTcpPidTable&& other) noexcept : m_table(other.m_table) { other.m_table = nullptr; }
    CTcpPidTable& operator=(CTcpPidTable&& other) noexcept
    {
        if (this != &other) {
            std::free(m_table);
            m_table = other.m_table;
            other.m_table = nullptr;
        }
        return *this;
    }
    PMIB_TCPTABLE_OWNER_PID get()
    {
        if (m_table == nullptr)
            throw std::logic_error("CTcpPidTable::get() -> nullptr");
        return m_table;
    }
    ~CTcpPidTable() { std::free(m_table); }
private:
    PMIB_TCPTABLE_OWNER_PID m_table;
};


bool tcp_caller_state_up(DWORD dwState)
{
    return dwState == MIB_TCP_STATE_ESTAB
        || dwState == MIB_TCP_STATE_FIN_WAIT1   // the caller can half-close its own end of the socket
        || dwState == MIB_TCP_STATE_FIN_WAIT2;
}


DWORD Get_Peer_Pid_From_Tcp_Loopback_Ports(int local_port, int peer_port)
{
    const DWORD nl_loopback = htonl(INADDR_LOOPBACK);
    const DWORD ns_peer_port = htons((u_short)peer_port);
    const DWORD ns_local_port = htons((u_short)local_port);

    CTcpPidTable table;
    PMIB_TCPTABLE_OWNER_PID p_table_owner = table.get();

    DWORD pid = 0;
    for (std::size_t i = 0; i < p_table_owner->dwNumEntries; i++) {
        if (p_table_owner->table[i].dwLocalAddr == nl_loopback
              && (p_table_owner->table[i].dwLocalPort & 0xFFFF) == ns_peer_port // we want the PID of the peer
              && p_table_owner->table[i].dwRemoteAddr == nl_loopback
              && (p_table_owner->table[i].dwRemotePort & 0xFFFF) == ns_local_port
              && tcp_caller_state_up(p_table_owner->table[i].dwState)) {
            pid = p_table_owner->table[i].dwOwningPid;
            break;
        }
    }
    return pid;
}


} // namespace


CUniqueHandle Get_Loopback_Tcp_Peer_Process_Handle(int local_port, int peer_port)
{
    DWORD pid = Get_Peer_Pid_From_Tcp_Loopback_Ports(local_port, peer_port);
    if (pid == 0)
        return CUniqueHandle();

    return CUniqueHandle(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
}
