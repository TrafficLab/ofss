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
 * Code for parsing logger related command line arguments.
 */

#include <stdlib.h>
#include <string.h>
#include <argp.h>
#include <uthash/utlist.h>
#include "lib/compiler.h"
#include "logger_int.h"
#include "logger_args.h"

#define LOG_LEVELS_NUM 8
static const char *log_level_names[] = {
    "EMERG",
    "ALERT",
    "CRIT",
    "ERR",
    "WARN",
    "NOTICE",
    "INFO",
    "DEBUG"
};

static inline int
str_idx_n(const char *arr[], size_t arr_len, char *str, size_t str_len);


static inline int
str_idx(const char *arr[], size_t arr_len, char *str);

/* Initializes the arguments container. */
void * MALLOC_ATTR
logger_args_new() {
    struct logger_args *args = malloc(sizeof(struct logger_args));
    args->head = NULL;
    return args;
}

void
logger_args_free(void *args_) {
    struct logger_args *args = (struct logger_args *)args_;

    struct logger_arg *inst, *next;
    LL_FOREACH_SAFE(args->head, inst, next) {
        free(inst->name);
        free(inst);
    }
    free(args);
}

/* Callback for parsing logger arguments. */
void
logger_args_parse(void *args_, char *arg, struct argp_state *state) {
    struct logger_args *args = (struct logger_args *)args_;

    if (arg == NULL) {
        struct logger_arg *inst = malloc(sizeof(struct logger_arg));
        inst->name = NULL;
        inst->level = LOG_DEBUG;
        inst->facility = LOG_STDOUT;
        LL_APPEND(args->head, inst);
        return;
    }

    // tokenize on separators
    char *log, *save_ptr;
    for (log = strtok_r(arg, ",", &save_ptr); log != NULL;
         log = strtok_r(NULL, ",", &save_ptr)) {

        struct logger_arg *inst = malloc(sizeof(struct logger_arg));

        // check if port has a colon
        char *colon = strchr(log, ':');

        if (colon == NULL) {
            // default setting
            int level = str_idx(log_level_names, LOG_LEVELS_NUM, log);
            if (level == -1) {
                argp_error(state, "Unable to parse log level: %s.", log);
            }
            inst->name = NULL;
            inst->level = level;
            inst->facility = LOG_STDOUT;
        } else {
            char *colon2 = strchr(colon+1, ':');

            if (colon2 == NULL) {
                // log is module:level
                int level = str_idx(log_level_names, LOG_LEVELS_NUM, colon + 1);
                if (level == -1) {
                    argp_error(state, "Unable to parse log level: %s.", log);
                }

                inst->name   = strncpy(malloc(colon - log + 1), log, colon - log);
                inst->name[colon - log] = '\0';
                inst->level    = level;
                inst->facility = LOG_STDOUT;
            } else {
                // log is module:level:facility
                int level = str_idx_n(log_level_names, LOG_LEVELS_NUM, colon + 1, colon2 - colon - 1);
                if (level == -1) {
                    argp_error(state, "Unable to parse log level: %s.", log);
                }

                inst->name   = strncpy(malloc(colon - log + 1), log, colon - log);
                inst->name[colon - log] = '\0';
                inst->level    = level;
                inst->facility = LOG_STDOUT; // TODO: parse facility
            }
        }
        LL_APPEND(args->head, inst);
    }
}


//* Returns the index of string (strncmp) in the string array, or -1 if not found. */
static inline int
str_idx_n(const char *arr[], size_t arr_len, char *str, size_t str_len) {
    size_t i;
    for (i = 0; i < arr_len; i++) {
        if (str_len == strlen(arr[i]) && strncmp(arr[i], str, str_len) == 0) {
            return i;
        }
    }

    return -1;
}

//* Returns the index of string in the string array, or -1 if not found. */
static inline int
str_idx(const char *arr[], size_t arr_len, char *str) {
    size_t i;
    for (i = 0; i < arr_len; i++) {
        if (strcmp(arr[i], str) == 0) {
            return i;
        }
    }

    return -1;
}
