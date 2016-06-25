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

// WARNING: this code is Win64 *only*
// In will *not* work under Win32 for a number of reasons...
// (some of them being that WOW64 is full of bugs, others being how this module
//  is designed to exploit unused bits)

#include <Windows.h>

#include <new>
#include <stdexcept>

#include <cstdio>
#include <cstdlib>
#include <cassert>

#include "job.h"
#include "win_except.h"
#include "ntsuspend.h"

enum // values must not change
{
    JPH_Tag_Suspended       = 0,
    JPH_Tag_Opened          = 1,
    JPH_Tag_Suspend_Failed  = 2,
    JPH_Tag_Skip_Idx        = 3,

    JPH_Tag_Mask = 3
};

enum // values must not change
{
    JPH_HUnknown    = 0,
    JPH_HOpenFailed = 1,
};

static bool is_real_handle(HANDLE h)
{
    return    ((ULONG_PTR)h & ~(ULONG_PTR)JPH_Tag_Mask)
           && (((ULONG_PTR)h & (ULONG_PTR)JPH_Tag_Mask) != JPH_Tag_Skip_Idx);
}

// precondition: is_real_handle(h)
static bool suspend_has_been_attempted(HANDLE h)
{
    return    (((ULONG_PTR)h & JPH_Tag_Mask) == JPH_Tag_Suspended)
           || (((ULONG_PTR)h & JPH_Tag_Mask) == JPH_Tag_Suspend_Failed);
}

static HANDLE tag_handle(HANDLE h, DWORD tag)
{
    return (HANDLE)(((ULONG_PTR)h & ~(ULONG_PTR)JPH_Tag_Mask) | tag);
}

static HANDLE untag_handle(HANDLE h)
{
    return (HANDLE)((ULONG_PTR)h & ~(ULONG_PTR)JPH_Tag_Mask);
}

/* Get_Skip_Value()
 *
 * Attempt to get the skip value of an entry.
 * If the entry does not exist or is not a skip entry, returns 0.
 */
static
SSIZE_T Get_Skip_Value(PJOBOBJECT_BASIC_PROCESS_ID_LIST pid_list, SSIZE_T idx)
{
    if (idx < 0 || idx >= (SSIZE_T)pid_list->NumberOfProcessIdsInList)
        return 0;
    DWORD msd = pid_list->ProcessIdList[idx] >> 32;
    if ((msd & JPH_Tag_Mask) != JPH_Tag_Skip_Idx)
        return 0;
    return (SSIZE_T)(msd >> 2);
}

static HANDLE cast_msd_to_HANDLE(DWORD msd)
{
#pragma warning( push )
// C4312: conversion from 'DWORD' to 'HANDLE' of greater size
// Here this is OK because 'msd' stores a (tagged) NT handle, which fits in 32-bits even on Win64.
#pragma warning( disable : 4312 )
    return (HANDLE)msd;
#pragma warning( pop )
}

static ULONG_PTR cast_HANDLE_to_msd(HANDLE hdl)
{
    if (hdl == NULL || hdl == INVALID_HANDLE_VALUE)
        return 0;

    return (ULONG_PTR)hdl;
}

/* Take_Handle_From_Pid_List()
 *
 * This function searches a PID in pid_list, and returns the associated
 * process handle, removing it from the pid_list at the same time.
 *
 * It is used to transfer process handles to a new PID list. A given PID is only
 * searched once in one pid_list. When a lookup succeeds, the ownership of the
 * handle is transferred to the caller. This allows to skip multiple entries
 * previously found by reusing the tagged handle field to store, instead, the
 * number of entries that shall be ignored (using JPH_Tag_Skip_Idx reserved for
 * this purpose). For expected workloads with some similar PID lists, this
 * should be enough to get O(n) perfs with a low constant factor and no extra
 * allocation.
 */
HANDLE Take_Handle_From_Pid_List(PJOBOBJECT_BASIC_PROCESS_ID_LIST pid_list, DWORD searched_pid)
{
    SSIZE_T idx = 0;

    // skip_value is the increment of idx that has been used to skip to the
    // current index, or 0 if we did not get to the current index by skipping.
    // This implies, at the beginning of the loop: (idx - skip_value) is the
    // entry from where we jumped to the current one (idx), or if we came to
    // the current entry without such a jump, (idx - skip_value) == idx.
    SSIZE_T skip_value = 0;

    while (idx < (SSIZE_T)pid_list->NumberOfProcessIdsInList) {
        DWORD pid = (DWORD)pid_list->ProcessIdList[idx];
        DWORD msd = pid_list->ProcessIdList[idx] >> 32;
        if ((msd & JPH_Tag_Mask) != JPH_Tag_Skip_Idx) {
            if (pid == searched_pid) {
                SSIZE_T skip_origin = idx - skip_value;
                assert(skip_origin >= 0); assert(skip_origin <= idx);
                SSIZE_T new_skip_value = skip_value + 1 + Get_Skip_Value(pid_list, idx + 1);
                DWORD new_orig_msd = ((DWORD)new_skip_value << 2) | JPH_Tag_Skip_Idx;
                pid_list->ProcessIdList[idx] = pid; // to clear the handle in case skip_origin != idx
                pid_list->ProcessIdList[skip_origin] = (pid_list->ProcessIdList[skip_origin] & 0xFFFFFFFF)
                                                       | ((ULONG_PTR)new_orig_msd << 32);
                return cast_msd_to_HANDLE(msd);
            } else {
                skip_value = 0;
                idx++;
            }
        } else { // JPH_Tag_Skip_Idx
            skip_value = (SSIZE_T)(msd >> 2);
            assert(skip_value > 0);
            idx += skip_value;
        }
    }
    return (HANDLE)JPH_HUnknown;
}

class CJobPidHandles {
public:
    CJobPidHandles() : m_pHPidList(nullptr) {}
    CJobPidHandles(CJobPidHandles&& other) : m_pHPidList(other.m_pHPidList) { other.m_pHPidList = nullptr; }
    CJobPidHandles& operator=(CJobPidHandles&& other)
    {
        if (this != &other) {
            free_hpid_list();
            m_pHPidList = other.m_pHPidList;
            other.m_pHPidList = nullptr;
        }
        return *this;
    }
    CJobPidHandles(HANDLE hJob);
    ~CJobPidHandles();

    bool open_suspend_round(CJobPidHandles& previous);

    void resume_all_suspended();

private:
    void free_hpid_list();
    HANDLE take_handle(DWORD pid) {
        if (!m_pHPidList)
            return NULL;
        else
            return Take_Handle_From_Pid_List(m_pHPidList, pid);
    }

private:
    PJOBOBJECT_BASIC_PROCESS_ID_LIST    m_pHPidList;
};

CJobPidHandles::CJobPidHandles(HANDLE hJob)
{
    size_t pid_list_buffer_size = 256;
    do {
        m_pHPidList = (PJOBOBJECT_BASIC_PROCESS_ID_LIST)std::calloc(1, pid_list_buffer_size);
        if (m_pHPidList == nullptr)
            throw std::bad_alloc();

        DWORD return_length = 0;

        if (!::QueryInformationJobObject(
                hJob,
                JobObjectBasicProcessIdList,
                m_pHPidList,
                (DWORD)pid_list_buffer_size,
                &return_length)) {

            DWORD last_err = ::GetLastError();

            std::free(m_pHPidList);
            m_pHPidList = nullptr;

            if (last_err == ERROR_MORE_DATA) {
                pid_list_buffer_size = return_length;
            } else {
                throw_system_error("QueryInformationJobObject failed", last_err);
            }
        }
    } while (m_pHPidList == nullptr);

    for (SSIZE_T idx = 0; idx < (SSIZE_T)m_pHPidList->NumberOfProcessIdsInList; idx++) {
        if (m_pHPidList->ProcessIdList[idx] >> 32 != 0) {
            std::free(m_pHPidList);
            throw std::domain_error("PID of more than 32-bits detected in a Job");
        }
    }
}

// to be called on a freshly constructed list
bool CJobPidHandles::open_suspend_round(CJobPidHandles& previous)
{
    bool activity = false;
    for (SSIZE_T idx = 0; idx < (SSIZE_T)m_pHPidList->NumberOfProcessIdsInList; idx++) {
        DWORD pid = (DWORD)m_pHPidList->ProcessIdList[idx];
        HANDLE hdl = previous.take_handle(pid);
        if (is_real_handle(hdl)) { // already opened
            if (suspend_has_been_attempted(hdl)) {
                m_pHPidList->ProcessIdList[idx] |= cast_HANDLE_to_msd(hdl) << 32;
            } else {
                // PID enumerated while handle opened => we are sure it is in the Job.
                // We could use IsProcessInJob(), but we are forced to do multiple rounds for
                // multiple reasons, so it is as easy to detect it like that, and we don't
                // have to think about IsProcessInJob() failures...
                DWORD tag = NT_Suspend(untag_handle(hdl)) ? JPH_Tag_Suspended : JPH_Tag_Suspend_Failed;
                m_pHPidList->ProcessIdList[idx] |= cast_HANDLE_to_msd(tag_handle(hdl, tag)) << 32;
                activity = true;
            }
        } else {
            // not opened, might be because:
            //  - this PID has not been seen in a previous round,
            //  - a previous attempt of OpenProcess() for this PID failed, in which case
            //    we don't know whether the same PID we see here is still for the same
            //    process, so we must retry
            HANDLE hProcess = ::OpenProcess(SYNCHRONIZE | PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION,
                                            FALSE,
                                            pid);
            if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
                if (((ULONG_PTR)hProcess & JPH_Tag_Mask) != 0)
                    throw std::domain_error("Process Handle with non-zero lsb bits");
                m_pHPidList->ProcessIdList[idx] |= cast_HANDLE_to_msd(tag_handle(hProcess, JPH_Tag_Opened)) << 32;
                activity = true;
            } else if (::GetLastError() != ERROR_INVALID_PARAMETER) {
                m_pHPidList->ProcessIdList[idx] |= (ULONG_PTR)JPH_HOpenFailed << 32;
            } // NOTE: ERROR_INVALID_PARAMETER OpenProcess errors are completely ignored (PID of a process that died in the meantime)
        }
    }
    return activity;
}

void CJobPidHandles::resume_all_suspended()
{
    assert(m_pHPidList);
    for (SSIZE_T idx = 0; idx < (SSIZE_T)m_pHPidList->NumberOfProcessIdsInList; idx++) {
        DWORD msd = m_pHPidList->ProcessIdList[idx] >> 32;
        DWORD msd_tag = msd & JPH_Tag_Mask;
        DWORD msd_value = msd & ~(DWORD)JPH_Tag_Mask;
        if (msd_tag == JPH_Tag_Suspended && msd_value != 0) { // NOTE: JPH_Tag_Suspended == 0
            NT_Resume(cast_msd_to_HANDLE(msd_value)); // XXX check?
            m_pHPidList->ProcessIdList[idx] |= (ULONG_PTR)JPH_Tag_Opened << 32;
        }
    }
}

void CJobPidHandles::free_hpid_list()
{
    // XXX we could warn about suspended processes in some cases here?
    if (m_pHPidList) {
        for (SSIZE_T idx = 0; idx < m_pHPidList->NumberOfProcessIdsInList; idx++) {
            DWORD msd = m_pHPidList->ProcessIdList[idx] >> 32;
            DWORD msd_tag = msd & JPH_Tag_Mask;
            DWORD msd_value = msd & ~(DWORD)JPH_Tag_Mask;
            if (msd_tag != JPH_Tag_Skip_Idx && msd_value != 0)
                ::CloseHandle(cast_msd_to_HANDLE(msd_value));
        }
        std::free(m_pHPidList);
        m_pHPidList = nullptr;
    }
}

CJobPidHandles::~CJobPidHandles()
{
    free_hpid_list();
}

class CSuspendedJobImpl {
public:
    CSuspendedJobImpl(HANDLE hJob);
    void resume();
private:
    CJobPidHandles                          m_job_pid_handles;
    HANDLE                                  m_hJob;
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION  m_orig_cpu_rate_control_info;
    bool                                    m_cpu_rate_control_applied;
};

CSuspendedJobImpl::CSuspendedJobImpl(HANDLE hJob)
  : m_job_pid_handles(),
    m_hJob(hJob),
    m_orig_cpu_rate_control_info{ 0 },
    m_cpu_rate_control_applied(false)
{
    bool activity;
    do {
        CJobPidHandles jph(hJob);
        activity = jph.open_suspend_round(m_job_pid_handles);
        m_job_pid_handles = std::move(jph);
    } while (activity);
}

void CSuspendedJobImpl::resume()
{
    if (m_cpu_rate_control_applied) {
        if (!::SetInformationJobObject(
                m_hJob,
                JobObjectCpuRateControlInformation,
                &m_orig_cpu_rate_control_info,
                sizeof(m_orig_cpu_rate_control_info))) {
            // here this is quite annoying, yet we can't do much
            Win32_perror("CSuspendedJobImpl::resume: SetInformationJobObject (disabling CPU rate limiting)");
        }
        m_cpu_rate_control_applied = false;
    }
    m_job_pid_handles.resume_all_suspended();
}

void CSuspendedJob::resume()
{
    if (m_pImpl)
    {
        m_pImpl->resume();
        free_pimpl();
    }
}

CSuspendedJob::~CSuspendedJob()
{
    free_pimpl();
}

void CSuspendedJob::free_pimpl()
{
    delete m_pImpl;
    m_pImpl = nullptr;
}

CSuspendedJob Suspend_Job_Object(HANDLE hJob)
{
    CSuspendedJob blah;
    blah.m_pImpl = new CSuspendedJobImpl(hJob);
    return blah;
}

/*BOOL Suspend_Job_Object(_In_ HANDLE hJob)
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

    try {
    CJobPidHandles job_plist(hJob);

    if (!Get_Job_Pid_List(hJob, &job_pid_list)) {
        Win32_perror("Suspend_Job_Object: Get_Job_Pid_List");
        result = FALSE;
        goto bye;
    }
    for (DWORD i = 0; i < job_pid_list->NumberOfProcessIdsInList; i++) {
        std::printf(" ZZZ: %u\n", (DWORD)job_pid_list->ProcessIdList[i]);
        HANDLE hProcess = ::OpenProcess(SYNCHRONIZE | PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION,
                                        FALSE,
                                        (DWORD)job_pid_list->ProcessIdList[i]);
        if (hProcess) {
            BOOL in_job;
            if (!::IsProcessInJob(hProcess, hJob, &in_job)) {
                ::CloseHandle(hProcess);
            } else {
                NT_Suspend(hProcess);
                // XXX: mark as suspended on success, ignored on failure
            }
        } else if (::GetLastError() != ERROR_INVALID_PARAMETER) { // note: no process with this PID => ERROR_INVALID_PARAMETER
            
        }
    }

bye:
    if (job_pid_list != NULL)
        ::HeapFree(GetProcessHeap(), 0, job_pid_list);

    if (rate_limit) {
        // we should do that only on resume...
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
*/