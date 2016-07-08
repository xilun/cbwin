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
#include <algorithm>

#include <cstdio>
#include <cstdlib>
#include <cassert>

#include "job.h"
#include "win_except.h"
#include "ntsuspend.h"


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
namespace
{


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
    JPH_HOpenFailed = 1,    // for another reason than simply if the process died
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

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
enum class EActivity
{
    None,
    Dubious,
    Glimpsed,
    Yes
};

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
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

    EActivity open_suspend_round(CJobPidHandles& previous);
    void only_keep_suspended();
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

static EActivity max_activity(EActivity a, EActivity b)
{
    return static_cast<EActivity>(std::max(static_cast<int>(a), static_cast<int>(b)));
}

// to be called on a freshly constructed list
EActivity CJobPidHandles::open_suspend_round(CJobPidHandles& previous)
{
    EActivity activity = EActivity::None;

    for (SSIZE_T idx = 0; idx < (SSIZE_T)m_pHPidList->NumberOfProcessIdsInList; idx++) {

        DWORD pid = (DWORD)m_pHPidList->ProcessIdList[idx];

        HANDLE hdl = previous.take_handle(pid); // this takes ownership of the handle

        if (is_real_handle(hdl)) { // already opened

            if (suspend_has_been_attempted(hdl)) {

                // propagate the handle and JPH_Tag_Suspended or JPH_Tag_Suspend_Failed from previous list
                m_pHPidList->ProcessIdList[idx] |= cast_HANDLE_to_msd(hdl) << 32;

                // We want EActivity::None to be a quite strong guarantee that the whole Job has
                // been suspended, so we consider a propagation of a JPH_Tag_Suspend_Failed handle
                // as EActivity::Dubious.
                if (((ULONG_PTR)hdl & JPH_Tag_Mask) == JPH_Tag_Suspend_Failed)
                    activity = max_activity(activity, EActivity::Dubious);

            } else {
                // PID enumerated while handle opened => we are sure it is in the Job.
                // We could use IsProcessInJob(), but we are forced to do multiple rounds to try to
                // cover for potential races with newly created processes, so it is easier to detect
                // it like that, and we don't have to think about IsProcessInJob() failures...
                DWORD tag = NT_Suspend(untag_handle(hdl)) ? JPH_Tag_Suspended : JPH_Tag_Suspend_Failed;

                // Save the process handle and if NT_Suspend() succeeded.
                // This will be propagated across future rounds.
                m_pHPidList->ProcessIdList[idx] |= cast_HANDLE_to_msd(tag_handle(hdl, tag)) << 32;

                // This process could have created others after we got the PID list, and we have made
                // some progress in this round, so we definitely want to schedule another one:
                activity = EActivity::Yes;
            }
        } else {
            // not opened, might be because:
            //  - this PID has not been seen in a previous round (or this is the first one),
            //  - a previous attempt of OpenProcess() for this PID failed, in which case
            //    we don't know whether the same PID we see here is still for the same
            //    process, so we should retry.

            HANDLE hProcess = ::OpenProcess(SYNCHRONIZE | PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION,
                                            FALSE,
                                            pid);

            if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
                if (((ULONG_PTR)hProcess & JPH_Tag_Mask) != 0)
                    throw std::domain_error("Process Handle with non-zero lsb bits");

                m_pHPidList->ProcessIdList[idx] |= cast_HANDLE_to_msd(tag_handle(hProcess, JPH_Tag_Opened)) << 32;

                // We only have opened, but not suspended yet (we actually are not sure this process
                // really is in the Job at this point). Schedule another round to make the suspend
                // attempt if still in the list while we have an handle.
                // See also the comment above the NT_Suspend() call.
                activity = EActivity::Yes;

            } else if (::GetLastError() == ERROR_INVALID_PARAMETER) {
                // The anticipated meaning is that the process with such PID has died and been reaped,
                // but I have no proof that there are no other conditions that could lead to here.
                // So we will retry a few times if this kind of situation persists across rounds
                // (because that could end up in the creation of suspendable processes), however we
                // would not make progress just by observing it over and over, so if this is the only
                // thing that happens we won't insist beyond reason.
                activity = max_activity(activity, EActivity::Glimpsed);

            } else { // "true" open failure -- process still here but could not open:

                m_pHPidList->ProcessIdList[idx] |= (ULONG_PTR)JPH_HOpenFailed << 32;

                // If we repeatedly try to open the same PID, and fail, there are even less
                // reasons to believe something interesting will eventually happen.
                // We could be each time observing a different process, but we should prefer
                // the simplest hypothesis: we are probably stuck on the same unexpected error.
                activity = max_activity(activity, (hdl == (HANDLE)JPH_HOpenFailed) ? EActivity::Dubious : EActivity::Glimpsed);
            }
        }
    }

    return activity;
}

void CJobPidHandles::only_keep_suspended()
{
    if (m_pHPidList)
    {
        SSIZE_T dest_idx = 0;
        for (SSIZE_T idx = 0; idx < (SSIZE_T)m_pHPidList->NumberOfProcessIdsInList; idx++) {
            DWORD msd = m_pHPidList->ProcessIdList[idx] >> 32;
            DWORD msd_tag = msd & JPH_Tag_Mask;
            DWORD msd_value = msd & ~(DWORD)JPH_Tag_Mask;
            if (msd_tag == JPH_Tag_Suspended && msd_value != 0) {
                m_pHPidList->ProcessIdList[dest_idx++] = m_pHPidList->ProcessIdList[idx];
            } else if (msd_tag != JPH_Tag_Skip_Idx && msd_value != 0) {
                ::CloseHandle(cast_msd_to_HANDLE(msd_value));
            }
        }
        m_pHPidList->NumberOfAssignedProcesses = (DWORD)dest_idx;
        m_pHPidList->NumberOfProcessIdsInList = (DWORD)dest_idx;
    }
}

void CJobPidHandles::resume_all_suspended()
{
    if (m_pHPidList)
    {
        for (SSIZE_T idx = 0; idx < (SSIZE_T)m_pHPidList->NumberOfProcessIdsInList; idx++) {
            DWORD msd = m_pHPidList->ProcessIdList[idx] >> 32;
            DWORD msd_tag = msd & JPH_Tag_Mask;
            DWORD msd_value = msd & ~(DWORD)JPH_Tag_Mask;
            if (msd_tag == JPH_Tag_Suspended && msd_value != 0) { // NOTE: JPH_Tag_Suspended == 0
                NT_Resume(cast_msd_to_HANDLE(msd_value));
                m_pHPidList->ProcessIdList[idx] |= (ULONG_PTR)JPH_Tag_Opened << 32;
            }
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


} // namespace


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
class CSuspendedJobImpl {
public:
    CSuspendedJobImpl(HANDLE hJob);
    void resume();
private:
    void job_cpu_rate_limit();
    void job_cpu_rate_restore();
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
    job_cpu_rate_limit();

    // XXX: handle exceptions

    EActivity activity = EActivity::Yes;
    int round = 0, round_after_progress = 0;
    do {
        CJobPidHandles jph(hJob);
        if (activity == EActivity::Yes)
            round_after_progress = round;
        activity = jph.open_suspend_round(m_job_pid_handles);
        m_job_pid_handles = std::move(jph);
        round++;
    } while (round < 1000 // there is no guarantee the algorithm terminates otherwise...
             && (   (activity == EActivity::Yes)
                 || (activity == EActivity::Glimpsed && round <= round_after_progress + 4)
                 || (activity == EActivity::Dubious  && round <= round_after_progress + 1)));

// examples:
// round | Yes -> round |  Dubious -> round | Dubious -> o
// round | Yes -> round | Glimpsed -> round | Glimpsed -> round | Glimpsed -> round | Glimpsed -> round | Glimpsed -> o
// 0              1                   2                   3                   4                   5
//
// Note that for Dubious to be detected, open must already have failed on the previous round. One more round is allowed,
// and if open still fails this will be the third time. (If Dubious comes after Glimpsed, we can bail out after only 2
// open failures, but we delay the stopping for at least the same number of rounds anyway.)

    m_job_pid_handles.only_keep_suspended();

    // After NtSuspendProcess() returns successfully, the observable state of the process (e.g. by
    // Task Manager or Process Hacker) will *eventually* be Suspended (if not resumed in the
    // meantime or already blocked on some syscalls), but progress toward this point seems to be
    // affected by the CPU rate limitation. So if we are quite sure that the whole Job has been
    // suspended, we disable the CPU rate limitation here to get a faster visibility by the rest
    // of the system -- otherwise it is only lifted on resume, so that the impact of potentially
    // not-suspended processes in the Job is somewhat limited.
    if (activity == EActivity::None)
        job_cpu_rate_restore();
}

void CSuspendedJobImpl::job_cpu_rate_limit()
{
    if (!m_cpu_rate_control_applied)
    {
        if (!::QueryInformationJobObject(
                    m_hJob,
                    JobObjectCpuRateControlInformation,
                    &m_orig_cpu_rate_control_info,
                    sizeof(m_orig_cpu_rate_control_info),
                    NULL))
            return;

        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION slow_job_cpu_rate;
        ZeroMemory(&slow_job_cpu_rate, sizeof(slow_job_cpu_rate));
        slow_job_cpu_rate.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        slow_job_cpu_rate.CpuRate = 1; // 0.01% CPU
        if (!::SetInformationJobObject(
                    m_hJob,
                    JobObjectCpuRateControlInformation,
                    &slow_job_cpu_rate,
                    sizeof(slow_job_cpu_rate)))
            return;

        m_cpu_rate_control_applied = true;
    }
}

void CSuspendedJobImpl::job_cpu_rate_restore()
{
    if (m_cpu_rate_control_applied) {
        if (!::SetInformationJobObject(
                m_hJob,
                JobObjectCpuRateControlInformation,
                &m_orig_cpu_rate_control_info,
                sizeof(m_orig_cpu_rate_control_info))) {
            // here this is quite annoying, yet we can't do much
            Win32_perror("CSuspendedJobImpl::job_cpu_rate_restore: SetInformationJobObject (disabling CPU rate limiting) failed");
        }
        m_cpu_rate_control_applied = false;
    }
}

void CSuspendedJobImpl::resume()
{
    job_cpu_rate_restore();
    m_job_pid_handles.resume_all_suspended();
}


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
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
