/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef LOGGER_H
#define LOGGER_H 1

#include <stdbool.h>
#include "lib/compiler.h"

enum logger_level {
    LOG_EMERG  = 0,
    LOG_ALERT  = 1,
    LOG_CRIT   = 2,
    LOG_ERR    = 3,
    LOG_WARN   = 4,
    LOG_NOTICE = 5,
    LOG_INFO   = 6,
    LOG_DEBUG  = 7
};

enum logger_facility {
    LOG_STDOUT = 0
};

struct logger;

void
logger_init();

bool
logger_is_enabled(const struct logger *logger, enum logger_level level);

void
logger_log(struct logger *logger, enum logger_level level, const char *format, ...) FORMAT_ATTR(printf, 3, 4);



#endif /* LOGGER_H */
