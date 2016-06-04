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
#include <sys/types.h>
#include <sys/socket.h>

#include "wrun.h"
#include "fd_info.h"

/**********************************************************************/

///
static ssize_t socket_nonblock_read(int fd, void *buf, size_t count)
{
    return recv(fd, buf, count, MSG_DONTWAIT);
}

static ssize_t socket_nonblock_write(int fd, const void *buf, size_t count)
{
    return send(fd, buf, count, MSG_DONTWAIT);
}

///
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

///
static ssize_t timer_nonblock_read(int fd, void *buf, size_t count)
{
    return read(fd, buf, count); // BUG
}

static ssize_t timer_nonblock_write(int fd, const void *buf, size_t count)
{
    return write(fd, buf, count); // BUG
}

/**********************************************************************/

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
