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
 * Common internal structures for loggers.
 */

#ifndef LOGGER_INT_H
#define LOGGER_INT_H 1

#include <pthread.h>
#include <stdio.h>
#include <uthash/uthash.h>
#include "logger.h"


struct logger {
    char                  *name;
    enum logger_level      level;
    enum logger_facility   facility;
    pthread_mutex_t       *mutex;
    char                   buffer[BUFSIZ];
    UT_hash_handle         hh;
};

struct logger_rule {
    bool                   exact;
    char                  *prefix;
    enum logger_level      level;
    enum logger_facility   facility;
    struct logger_rule    *next;
};

struct logger_rules {
    struct logger_rule  *head;
};

struct logger_arg {
    char                  *name;
    enum logger_level      level;
    enum logger_facility   facility;
    struct logger_arg     *next;
};

struct logger_args {
    struct logger_arg  *head;
};

#endif /* LOGGER_INT_H */
