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

#ifndef WRUN_COMMON_H
#define WRUN_COMMON_H

#include <stdlib.h>
#include <stdbool.h>

bool is_absolute_drive_fs_path(const char* s);

// precondition: is_absolute_drive_fs_path(path)
// the returned value must be freed by the caller
char* convert_drive_fs_path_to_win32(const char* path);

static inline const char* shift(int *pargc, char ***pargv)
{
    if (*pargc) {
        const char *shifted = **pargv;
        (*pargc)--;
        (*pargv)++;
        return shifted;
    } else {
        abort();
    }
}

#endif // WRUN_COMMON_H
