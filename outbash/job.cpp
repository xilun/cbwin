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

#include <cstdio>

#include "job.h"
#include "win_except.h"
#include "ntsuspend.h"

static BOOL Get_Job_Pid_List(_In_ HANDLE hJob, _Out_ PJOBOBJECT_BASIC_PROCESS_ID_LIST *pHeapPidList)
{
    size_t pid_list_buffer_size = 2048 - 16;
    do {
        *pHeapPidList = (PJOBOBJECT_BASIC_PROCESS_ID_LIST)::HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pid_list_buffer_size);
        if (*pHeapPidList == NULL)
            return FALSE;
        DWORD return_length;
        if (!::QueryInformationJobObject(
                hJob,
                JobObjectBasicProcessIdList,
                *pHeapPidList,
                (DWORD)pid_list_buffer_size,
                &return_length)) {
            DWORD last_err = ::GetLastError();
            if (last_err == ERROR_MORE_DATA) {
                ::HeapFree(GetProcessHeap(), 0, *pHeapPidList);
                *pHeapPidList = NULL;
                pid_list_buffer_size = return_length;
            } else {
                ::HeapFree(GetProcessHeap(), 0, *pHeapPidList);
                *pHeapPidList = NULL;
                ::SetLastError(last_err);
                return FALSE;
            }
        }
    } while (*pHeapPidList == NULL);

    return TRUE;
}

BOOL Suspend_Job_Object(_In_ HANDLE hJob)
{
    PJOBOBJECT_BASIC_PROCESS_ID_LIST job_pid_list;
    BOOL result = TRUE;
    bool rate_limit = true;

    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION orig_job_cpu_rate;
    if (!::QueryInformationJobObject(
                hJob,
                JobObjectCpuRateControlInformation,
                &orig_job_cpu_rate,
                sizeof(orig_job_cpu_rate),
                NULL))
        rate_limit = false;

    if (rate_limit) {
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION slow_job_cpu_rate;
        ZeroMemory(&slow_job_cpu_rate, sizeof(slow_job_cpu_rate));
        slow_job_cpu_rate.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        slow_job_cpu_rate.CpuRate = 1; // 0.01% CPU
        if (!::SetInformationJobObject(
                    hJob,
                    JobObjectCpuRateControlInformation,
                    &slow_job_cpu_rate,
                    sizeof(slow_job_cpu_rate)))
            rate_limit = false;
    }

    if (!Get_Job_Pid_List(hJob, &job_pid_list)) {
        Win32_perror("Suspend_Job_Object: Get_Job_Pid_List");
        result = FALSE;
        goto bye;
    }
    for (DWORD i = 0; i < job_pid_list->NumberOfProcessIdsInList; i++) {
        std::printf(" ZZZ: %u\n", (DWORD)job_pid_list->ProcessIdList[i]);
    }

bye:
    if (job_pid_list != NULL)
        ::HeapFree(GetProcessHeap(), 0, job_pid_list);

    if (rate_limit) {
        if (!::SetInformationJobObject(
                hJob,
                JobObjectCpuRateControlInformation,
                &orig_job_cpu_rate,
                sizeof(orig_job_cpu_rate))) {
            // for the others, we could do without, this time this is more annoying, yet we can't do much
            Win32_perror("Suspend_Job_Object: SetInformationJobObject (disabling CPU rate limiting)");
        }
    }

    return result;
}
