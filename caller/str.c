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

#include "str.h"

#include <string.h>
#include <stdlib.h>

#include "xalloc.h"

struct string string_create(const char* init)
{
    struct string result;
    result.length = strlen(init);
    result.capacity = result.length;
    result.str = xmalloc(result.capacity + 1);
    memcpy(result.str, init, result.length + 1);
    return result;
}

static void string_reserve(struct string* s, size_t new_capacity)
{
    if (new_capacity > s->capacity) {
        s->capacity = new_capacity;
        s->str = xrealloc(s->str, s->capacity + 1);
    }
}

static void string_exp_grow(struct string* s, size_t req_capa)
{
    if (req_capa > s->capacity) {
        if (req_capa < s->capacity * 2 + 1)
            req_capa = s->capacity * 2 + 1;
        string_reserve(s, req_capa);
    }
}

void string_assign(struct string* restrict s, const char* restrict rhs)
{
    size_t rhs_len = strlen(rhs);
    string_exp_grow(s, rhs_len);
    memcpy(s->str, rhs, rhs_len + 1);
    s->length = rhs_len;
}

void string_append(struct string* restrict s, const char* restrict rhs)
{
    size_t rhs_len = strlen(rhs);
    string_exp_grow(s, s->length + rhs_len);
    memcpy(&s->str[s->length], rhs, rhs_len + 1);
    s->length += rhs_len;
}

void string_destroy(struct string* s)
{
    free(s->str);
    s->str = NULL;
    s->capacity = 0;
    s->length = 0;
}
