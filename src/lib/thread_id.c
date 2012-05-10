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
 * Thread_id is used for allocating a unique integer identifier
 * for each thread, which is convenient for debugging (logs).
 */

#include <pthread.h>
#include <stdlib.h>
#include "lib/compiler.h"
#include "lib/logger_names.h"
#include "logger/logger.h"
#include "logger/logger_mgr.h"
#include "thread_id.h"

static size_t            next_id;
static pthread_mutex_t  *mutex;
static pthread_key_t     key;
static struct logger    *logger;


/* Callback to free the thread's id when the thread is destroyed. */
static void
free_id(void *data) {
    free(data);
}

/* Static initializer. */
void
thread_id_init() {
    next_id = 0;
    mutex = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(mutex, NULL);

    logger = logger_mgr_get(LOGGER_NAME_THREAD_ID);

    if (pthread_key_create(&key, free_id) != 0) {
        logger_log(logger, LOG_ERR, "Unable to create pthread key.");
    }

    thread_id_set();
}

/* Sets the identifier of the current thread. */
void
thread_id_set() {
    size_t *thread_id = malloc(sizeof(size_t));

    pthread_mutex_lock(mutex);
    *thread_id = next_id;
    next_id++;
    pthread_mutex_unlock(mutex);

    if (pthread_setspecific(key, thread_id) != 0) {
        logger_log(logger, LOG_ERR, "Unable to set pthread key.");
    }
}

/* Returns the identifier of the current thread, or -1. */
ssize_t
thread_id_get() {
    size_t *thread_id = pthread_getspecific(key);
    if (thread_id != NULL) {
        return *thread_id;
    } else {
        return -1;
    }
}
