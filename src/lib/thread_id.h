/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef THREAD_ID_H
#define THREAD_ID_H 1

#include <sys/types.h>

void
thread_id_init();

void
thread_id_set();

ssize_t
thread_id_get();

#endif /* THREAD_ID_H */
