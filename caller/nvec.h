/*
 * Copyright (c) 2008, by Attractive Chaos <attractor@live.co.uk>
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

// adapted from https://github.com/attractivechaos/klib/blob/master/kvec.h
// biggest diff: we avoid explicit 'type' macro params thanks to gcc extensions

#ifndef WRUN_NVEC_H
#define WRUN_NVEC_H

#include <stdlib.h>
#include <string.h>
#include "xalloc.h"

#define NVEC_BUILD_BUG_ON(e)    ((void)(sizeof(struct { int:-!!(e); })))
#define __nvec_same_type(a, b)  __builtin_types_compatible_p(__typeof__ (a), __typeof__ (b))

#define nvec_t(type)    struct { size_t n, m; type *a; }

#define nv_init(v)      do { __typeof__ (v) *_vptr = &(v); _vptr->n = _vptr->m = 0; _vptr->a = 0; } while (0)
#define nv_destroy(v)   do { free((v).a); nv_init(v); } while (0)
#define nv_A(v, i)      ((v).a[(i)])
#define nv_pop(v)       ({ __typeof__ (v) *_vptr = &(v); _vptr->a[--(_vptr->n)]; })
#define nv_size(v)      ((v).n)
#define nv_capacity(v)  ((v).m)

#define nv_reserve(v, s)    do {                                                                    \
                                __typeof__ (v) *_vptr = &(v);                                       \
                                size_t _s = (s);                                                    \
                                if (_s > _vptr->m) {                                                \
                                    _vptr->m = _s;                                                  \
                                    _vptr->a = xrealloc(_vptr->a, sizeof (*(_vptr->a)) * _vptr->m); \
                                }                                                                   \
                            } while (0)

#define nv_copy(v1, v0)     do {                                                                    \
                                __typeof__ (v0) *_vptr0 = &(v0);                                    \
                                __typeof__ (v1) *_vptr1 = &(v1);                                    \
                                NVEC_BUILD_BUG_ON(!__nvec_same_type(*(_vptr0->a), *(_vptr1->a)));   \
                                if (_vptr1->m < _vptr0->n)                                          \
                                    nv_reserve(*_vptr1, _vptr0->n);                                 \
                                _vptr1->n = _vptr0->n;                                              \
                                memcpy(_vptr1->a, _vptr0->a, sizeof (*(_vptr1->a)) * _vptr0->n);    \
                            } while (0)

#define nv_pushp(v)         ({                                                                      \
                                __typeof__ (v) *_vptr = &(v);                                       \
                                if (_vptr->n >= _vptr->m) {                                         \
                                    _vptr->m = _vptr->n ? _vptr->n*2 : 2;                           \
                                    _vptr->a = xrealloc(_vptr->a, sizeof (*(_vptr->a)) * _vptr->m); \
                                }                                                                   \
                                (_vptr->a + (_vptr->n++));                                          \
                            })

#define nv_push(v, x)       do { *nv_pushp(v) = (x); } while (0)

#define nv_ap(v, i)         ({                                                                          \
                                size_t _idx = (i);                                                      \
                                __typeof__ (v) *_vptr = &(v);                                           \
                                if (_idx >= _vptr->n) {                                                 \
                                    if (_idx >= _vptr->m) {                                             \
                                        _vptr->m *= 2;                                                  \
                                        if (_idx >= _vptr->m)                                           \
                                            _vptr->m = _idx + 1;                                        \
                                        _vptr->a = xrealloc(_vptr->a, sizeof (*(_vptr->a)) * _vptr->m); \
                                    }                                                                   \
                                    _vptr->n = _idx + 1;                                                \
                                }                                                                       \
                                (_vptr->a + _idx);                                                      \
                            })

#define nv_a(v, i)          (*nv_ap(v, i))

#endif // WRUN_NVEC_H
