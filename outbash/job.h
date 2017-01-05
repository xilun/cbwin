#pragma once

#include <WinDef.h>
#include <memory>

class CSuspendedJob {
public:
    friend CSuspendedJob Suspend_Job_Object(HANDLE hJob);
    void resume(); // Postcondition: this->is_empty()
    bool is_empty() const { return !m_pImpl; }

private:
    class Impl;
    struct ImplDeleter { void operator()(Impl*) const; };
    std::unique_ptr<Impl, ImplDeleter> m_pImpl;
};

// A free function is preferred to a constructor or a static method here:
//  - with a constructor:   'CSuspendedJob suspended_job(hJob);'  would not be very clear.
//  - with a static method: 'CSuspendedJob suspended_job; suspended_job.Suspend_Job_Object(hJob);'  would compile but would be an error.
// Postcondition: !result.is_empty()
CSuspendedJob Suspend_Job_Object(HANDLE hJob);
