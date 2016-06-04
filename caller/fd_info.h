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

#pragma once

#include <stdbool.h>

#include <sys/stat.h>

typedef ssize_t (*read_function)(int fd, void *buf, size_t count);
typedef ssize_t (*write_function)(int fd, const void *buf, size_t count);

struct fd_info_struct {

    /* identity: */
    int fd;
    bool is_bad;
    bool is_dev_null;
    bool is_a_tty;
    bool is_socket;
    struct stat stbuf;

    bool nonblock_ignored;
    bool setfl_nonblock_forbidden;  // inherited fds => forbidden
    bool setfl_nonblock_needed;

    /* operations: */
    read_function   nonblock_read;
    write_function  nonblock_write;

    /* runtime attribute, also depends on cmd line options: */
    bool redirect;
};

void fd_info_global_init(void);
void fd_info_init(struct fd_info_struct *info, int fd, bool inherited);
void fd_info_setup_nonblock(struct fd_info_struct *info);
void fd_info_virtual_close_fd(struct fd_info_struct *info);
ssize_t fd_info_nonblock_read(struct fd_info_struct *info, void *buf, size_t count);
ssize_t fd_info_nonblock_write(struct fd_info_struct *info, const void *buf, size_t count);

void fd_info_global_dump_stats(void);
