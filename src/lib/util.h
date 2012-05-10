/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef UTIL_H
#define UTIL_H 1

#include <stddef.h>
#include <netinet/in.h>
#include "lib/compiler.h"

#define MIN(x,y) (x < y ? x : y)
#define MAX(x,y) (x > y ? x : y)

// use when printing strings to display a default value for null pointers
#define STR_DEF(s, def) s == NULL ? def : s

#endif /* UTIL_H */
