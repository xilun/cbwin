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

#include "common.h"

#include <string.h>
#include <stdbool.h>

#include "xalloc.h"

#define MNT_DRIVE_FS_PREFIX "/mnt/"

bool is_absolute_drive_fs_path(const char* s)
{
    return (strncmp(s, MNT_DRIVE_FS_PREFIX, strlen(MNT_DRIVE_FS_PREFIX)) == 0)
           && s[strlen(MNT_DRIVE_FS_PREFIX)] >= 'a'
           && s[strlen(MNT_DRIVE_FS_PREFIX)] <= 'z'
           && (s[strlen(MNT_DRIVE_FS_PREFIX) + 1] == '/'
               || s[strlen(MNT_DRIVE_FS_PREFIX) + 1] == '\0');
}

// precondition: is_absolute_drive_fs_path(path)
char* convert_drive_fs_path_to_win32(const char* path)
{
    char* result = xmalloc(4 + strlen(path));
    result[0] = path[strlen(MNT_DRIVE_FS_PREFIX)];
    result[1] = ':';
    result[2] = '\\';
    strcpy(result + 3, path + strlen(MNT_DRIVE_FS_PREFIX) + 2);
    size_t i;
    for (i = 3; result[i]; i++)
        if (result[i] == '/')
            result[i] = '\\';
    return result;
}
