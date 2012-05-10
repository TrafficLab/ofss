/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <time.h>
#include "lib/compiler.h"
#include "lib/thread_id.h"
#include "logger_int.h"
#include "logger.h"


/* Logger instance handling. */

static const char *log_level_print[] = {
    "EMRG",
    "ALRT",
    "CRIT",
    "ERR ",
    "WARN",
    "NOTI",
    "INFO",
    "DBG "
};

static pthread_mutex_t  *stdout_mutex;

/* Static initializer. */
void
logger_init() {
    stdout_mutex = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(stdout_mutex, NULL);
}


/* Checks whether the logger is enabled for the given log level. */
bool
logger_is_enabled(const struct logger *logger, enum logger_level level) {
    pthread_mutex_lock(logger->mutex);
    bool ret = (logger->level >= level);
    pthread_mutex_unlock(logger->mutex);
    return ret;
}

/* Creates a log entry with the logger. */
void FORMAT_ATTR(printf, 3, 4)
logger_log(struct logger *logger, enum logger_level level, const char *format, ...) {
    pthread_mutex_lock(logger->mutex);
    if (logger->level >= level) {
        time_t    nowt;
        struct tm nowtm;
        time(&nowt);
        localtime_r(&nowt, &nowtm);

        int len;
        size_t buf_len;
        len = strftime(logger->buffer, BUFSIZ, "%T", &nowtm);
        // TODO: validate len
        buf_len = len;
        len = snprintf(logger->buffer + buf_len, BUFSIZ - buf_len, " [%d] %-14s %s ", thread_id_get(), logger->name, log_level_print[level]);
        // TODO: validate len
        buf_len += len;

        va_list args;
        va_start(args, format);
        len = vsnprintf(logger->buffer + buf_len, BUFSIZ - buf_len, format, args);
        // TODO: validate len
        va_end(args);

        if (logger->facility == LOG_STDOUT) {
            pthread_mutex_lock(stdout_mutex);
            puts(logger->buffer); // NOTE: puts appends newline
            pthread_mutex_unlock(stdout_mutex);
        }
    }
    pthread_mutex_unlock(logger->mutex);
}
