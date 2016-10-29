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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

void output_err(const char* s)
{
    ssize_t len = (ssize_t)strlen(s);
    ssize_t where = 0;
    while (len - where > 0) {
        ssize_t res = write(STDERR_FILENO, s + where, len - where);
        if (res < 0) {
            if (errno != EINTR)
                return;
        } else {
            where += res;
        }
    }
}

void terminate_nocore()
{
    // we use SIGKILL because it's reliable, does not dump core, and Windows
    // does not have it, so if we ever get crazy enough to propagate
    // termination by signal, the caller will still be able to distinguish
    // between local and Win32 failures.
    kill(getpid(), SIGKILL);
    abort(); // fallback, should not happen
}

void* xmalloc(size_t sz)
{
    void* result = malloc(sz);
    if (result == NULL) {
        output_err("malloc failed\n");
        abort();
    }
    return result;
}

void* xrealloc(void *ptr, size_t sz)
{
    void* result = realloc(ptr, sz);
    if (result == NULL) {
        output_err("realloc failed\n");
        abort();
    }
    return result;
}

char* xstrdup(const char* s)
{
    char* result = strdup(s);
    if (result == NULL) {
        output_err("strdup failed\n");
        abort();
    }
    return result;
}

void* xcalloc(size_t nmemb, size_t size)
{
    void* result = calloc(nmemb, size);
    if (result == NULL) {
        output_err("calloc failed\n");
        abort();
    }
    return result;
}

const char* shift(int *pargc, char ***pargv)
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
