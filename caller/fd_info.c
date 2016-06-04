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

#define _XOPEN_SOURCE 700
#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "wrun.h"
#include "fd_info.h"

/**********************************************************************/

//////////////////// SOCKET
static ssize_t socket_nonblock_read(int fd, void *buf, size_t count)
{
    return recv(fd, buf, count, MSG_DONTWAIT);
}

static ssize_t socket_nonblock_write(int fd, const void *buf, size_t count)
{
    return send(fd, buf, count, MSG_DONTWAIT);
}

//////////////////// BADF
static ssize_t fake_read_badf(int fd, void *buf, size_t count)
{
    (void)fd; (void)buf; (void)count;
    return 0;
}

static ssize_t fake_write_badf(int fd, const void *buf, size_t count)
{
    (void)fd; (void)buf;
    if (count > SSIZE_MAX) {
        errno = EINVAL;
        return -1;
    }
    return count;
}

//////////////////// NONBLOCK'ish SIMULATION WITH A TIMER
#define INITIAL_NONBLOCK_TIMER  50000
volatile sig_atomic_t first_alarm;

static long long usecs;
static long long max_usecs;
static int alarm_count;
static int nb_eintr;
static int nb_rw;

static void alarm_handler(int signum)
{
    (void)signum;

    static struct itimerval backoff_timer = {{0,0},{0,INITIAL_NONBLOCK_TIMER}};

    if (first_alarm) {
        usecs = INITIAL_NONBLOCK_TIMER;
        first_alarm = false;
    }

    // stats:
    if (usecs > max_usecs)
        max_usecs = usecs;
    alarm_count++;

    // exponential backoff:
    usecs *= 2;
    if (usecs > 60000000)
        usecs = 60000000; // 1 min

    backoff_timer.it_value.tv_sec = usecs / 1000000;
    backoff_timer.it_value.tv_usec = usecs % 1000000;
    setitimer(ITIMER_REAL, &backoff_timer, NULL);
}

// precondition: SIGALRM ignored, timer is disarmed
static void setup_alarm_handler(void)
{
    first_alarm = true;

    struct sigaction sa;
    sa.sa_handler = alarm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGALRM, &sa, NULL);

    static const struct itimerval it = {{0,0},{0,INITIAL_NONBLOCK_TIMER}};
    setitimer(ITIMER_REAL, &it, NULL);
}

static void disarm_alarm(void)
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    sigprocmask(SIG_BLOCK, &set, NULL);
    static const struct itimerval it_disarm = {{0,0},{0,0}};
    setitimer(ITIMER_REAL, &it_disarm, NULL);
    signal(SIGALRM, SIG_IGN);
    sigprocmask(SIG_UNBLOCK, &set, NULL);
}

static ssize_t timer_nonblock_read(int fd, void *buf, size_t count)
{
    setup_alarm_handler();
    //
        nb_rw++;
        ssize_t result = read(fd, buf, count);
        int save_errno = errno;
        if (result < 0 && save_errno == EINTR) {
            nb_eintr++;
            save_errno = EAGAIN;
        }
    //
    disarm_alarm();

    errno = save_errno;
    return result;
}

static ssize_t timer_nonblock_write(int fd, const void *buf, size_t count)
{
    setup_alarm_handler();
    //
        nb_rw++;
        ssize_t result = write(fd, buf, count);
        int save_errno = errno;
        if (result < 0 && save_errno == EINTR) {
            nb_eintr++;
            save_errno = EAGAIN;
        }
    //
    disarm_alarm();

    errno = save_errno;
    return result;
}

/**********************************************************************/

void fd_info_global_init(void)
{
    signal(SIGALRM, SIG_IGN);
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    sigprocmask(SIG_UNBLOCK, &set, NULL);
}

void fd_info_global_dump_stats(void)
{
    fprintf(stderr, "max usecs=%lld count=%d nb_eintr=%d nb_rw=%d\n", max_usecs, alarm_count, nb_eintr, nb_rw);
}

void fd_info_init(struct fd_info_struct *info, int fd, bool inherited)
{
    memset(info, 0, sizeof *info);

    info->fd = fd;
    info->nonblock_read  = read;    // provisional
    info->nonblock_write = write;   // provisional

    int r = fstat(info->fd, &info->stbuf);
    if (r != 0) {
        if (errno == EBADF) {
            info->is_bad = true;
            info->nonblock_ignored = true;
            info->setfl_nonblock_forbidden = true;
            info->nonblock_read = fake_read_badf;
            info->nonblock_write = fake_write_badf;
            return;
        } else {
            dprintf(STDERR_FILENO, "%s: fstat(%d, &st) failed: %s\n", tool_name, fd, strerror(errno));
            abort();
        }
    }

    info->setfl_nonblock_forbidden = inherited;

    // under Linux, the major and minor of /dev/null is fixed:
    if (S_ISCHR(info->stbuf.st_mode) && major(info->stbuf.st_rdev) == 1
                                     && minor(info->stbuf.st_rdev) == 3) {
        info->is_dev_null = true;
        info->nonblock_ignored = true;
    } else if (S_ISSOCK(info->stbuf.st_mode)) {
        info->is_socket = true;
    } else if (S_ISREG(info->stbuf.st_mode) || S_ISBLK(info->stbuf.st_mode)) {
        info->nonblock_ignored = true;
    } else if (isatty(info->fd)) {
        info->is_a_tty = true;
    }

    if (info->is_socket) {
        info->nonblock_read  = socket_nonblock_read;
        info->nonblock_write = socket_nonblock_write;
    } else if (!info->nonblock_ignored && info->setfl_nonblock_forbidden) {
        info->nonblock_read  = timer_nonblock_read;
        info->nonblock_write = timer_nonblock_write;
    } else if (!info->nonblock_ignored) {
        info->setfl_nonblock_needed = true;
    }
}

static void fd_set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
        dprintf(STDERR_FILENO, "%s: fcntl(%d, F_GETFL) failed: %s\n", tool_name, fd, strerror(errno));
        abort();
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        dprintf(STDERR_FILENO, "%s: fcntl(%d, F_SETFL, flags | O_NONBLOCK) failed: %s\n", tool_name, fd, strerror(errno));
        abort();
    }
}

void fd_info_setup_nonblock(struct fd_info_struct *info)
{
    if (info->setfl_nonblock_needed)
        fd_set_nonblock(info->fd);
}

ssize_t fd_info_nonblock_read(struct fd_info_struct *info, void *buf, size_t count)
{
    return info->nonblock_read(info->fd, buf, count);
}

ssize_t fd_info_nonblock_write(struct fd_info_struct *info, const void *buf, size_t count)
{
    return info->nonblock_write(info->fd, buf, count);
}

void fd_info_virtual_close_fd(struct fd_info_struct *info)
{
    if (info->fd >= 0) {
        if (info->fd != 2)  // keep stderr open for our own messages
            close(info->fd);
        info->fd = -1;
    }
}
