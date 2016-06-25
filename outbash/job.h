#pragma once

class CSuspendedJobImpl;

class CSuspendedJob {
public:
    friend CSuspendedJob Suspend_Job_Object(HANDLE hJob);
    void resume();

    // C++ is too shitty to allow usable and efficient pImpl designs based on unique_ptr,
    // so we have to also write all the boring stuff ourselves :/
    // This is even more ridiculous because the C++ pImpl pattern needs too much
    // boilerplate forwarding code in the first place, because of previous shortcomings
    // of the language (in contrast with a simple opaque structure pattern with explicit
    // allocators). GRRRRRRRR! I should have stuck to C :/
    CSuspendedJob() : m_pImpl(nullptr) {}
    CSuspendedJob(CSuspendedJob&& other) : m_pImpl(other.m_pImpl) { other.m_pImpl = nullptr; }
    CSuspendedJob& operator=(CSuspendedJob&& other)
    {
        if (this != &other) {
            free_pimpl();
            m_pImpl = other.m_pImpl;
            other.m_pImpl = nullptr;
        }
        return *this;
    }
    ~CSuspendedJob();

private:
    void free_pimpl();
    CSuspendedJobImpl*  m_pImpl;
};

// A free function is preferred to a constructor or a static method here:
//  - with a constructor:   'CSuspendedJob suspended_job(hJob);'  would not be very clear.
//  - with a static method: 'CSuspendedJob suspended_job; suspended_job.Suspend_Job_Object(hJob);'  would compile but would be an error.
CSuspendedJob Suspend_Job_Object(HANDLE hJob);
