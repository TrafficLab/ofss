/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

/*
 * Compiler macros; made portable.
 */

#ifndef COMPILER_H
#define COMPILER_H 1

#ifdef __GNUC__
#if __GNUC__ >= 4

#define inline                 inline __attribute__((always_inline))
#define CONST_ATTR             __attribute__((const))
#define CONTAINER_OF(ptr, type, member)                \
({const typeof( ((type *)0)->member ) *__mptr = (ptr); \
(type *)( (char *)__mptr - offsetof(type,member) );})
#define FORMAT_ATTR(a, s, f)   __attribute__((format (a, s, f)))
#define MALLOC_ATTR            __attribute__((malloc))
#define PACKED_ATTR            __attribute__((packed))
#define PURE_ATTR              __attribute__((pure))
#define UNUSED_ATTR            __attribute__((unused))
#define LIKELY(x)              __builtin_expect(!!(x), 1)
#define UNLIKELY(x)            __builtin_expect(!!(x), 0)

#endif
#else

#define CONST_ATTR
#define CONTAINER_OF(ptr, type, member)               \
((type *) ((char *)(ptr) - offsetof(type, member)))
#define FORMAT_ATTR(a, s, f)
#define MALLOC_ATTR
#define PACKED_ATTR
#define PURE_ATTR
#define UNUSED_ATTR
#define LIKELY(x)         (x)
#define UNLIKELY(x)       (x)

#endif

#endif /* COMPILER_H */
