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

#include "xalloc.h"

#include <stdlib.h>
#include <string.h>

#include "err.h"

void* xmalloc(size_t sz)
{
    if (sz == 0) sz = 1;

    void* result = malloc(sz);
    if (result == NULL) {
        output_err("malloc failed\n");
        abort();
    }
    return result;
}

void* xrealloc(void *ptr, size_t sz)
{
    if (sz == 0) sz = 1;

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
    if (nmemb == 0 || size == 0) {
        nmemb = 1;
        size = 1;
    }

    void* result = calloc(nmemb, size);
    if (result == NULL) {
        output_err("calloc failed\n");
        abort();
    }
    return result;
}
