/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <uthash/utlist.h>
#include "lib/compiler.h"
#include "lib/logger_names.h"
#include "logger_mgr.h"
#include "logger_int.h"

/* Manager for logger instances. */

#define LOGGER_NAME_MAX_LEN 16

static pthread_mutex_t      *logger_mgr_mutex;
static struct logger        *loggers;
static struct logger_rules  *rules;

static struct logger        *logger;

/* Static initializer. */
void
logger_mgr_init() {
    logger_init();

    logger_mgr_mutex = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(logger_mgr_mutex, NULL);
    loggers = NULL;

    rules = malloc(sizeof(struct logger_rules));
    rules->head = NULL;

    logger_mgr_default_rule(LOG_WARN, LOG_STDOUT);

    logger = logger_mgr_get(LOGGER_NAME_LOGGER_MGR);

}

/* Processes the parsed command line arguments. */
void
logger_mgr_args(void *args_) {
    if (args_ == NULL) {
        return;
    }

    struct logger_args *args = (struct logger_args *)args_;

    struct logger_arg *inst;
    LL_FOREACH(args->head, inst) {

        if (inst->name == NULL) {
            logger_mgr_default_rule(inst->level, inst->facility);
        } else {
            logger_mgr_add_rule(inst->name, inst->level, inst->facility);
        }
    }

    logger_log(logger, LOG_INFO, "Arguments processed.");
}

/* Finds the most explicit rule for the logger.
 * NOTE must be called with mutex locked. */
static struct logger_rule *
find_matching_rule(char *name) {
    struct logger_rule *best = NULL;
    size_t best_len = 0;

    struct logger_rule *rule;
    LL_FOREACH(rules->head, rule) {
        if (rule->exact) {
            if (strcmp(name, rule->prefix) == 0) {
                return rule;
            }
        } else {
            if (strlen(rule->prefix) > strlen(name)) {
                continue;
            }
            if (strncmp(name, rule->prefix, strlen(rule->prefix)) == 0) {
                if (strlen(rule->prefix) >= best_len) { // >= because of default rule
                    best = rule;
                    best_len = strlen(rule->prefix);
                }
            }
        }
    }

    return best;
}

/* Creates a new logger instance with the given name.
 * NOTE must be called with mutex locked. */
static struct logger * MALLOC_ATTR
logger_new(char *name) {
    struct logger *l = malloc(sizeof(struct logger));

    l->mutex = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(l->mutex, NULL);

    l->name = strdup(name);

    struct logger_rule *rule = find_matching_rule(name);
    assert(rule != NULL);

    l->level = rule->level;
    l->facility = rule->facility;

    return l;
}

/* If a logger with the given name exists, returns it;
 * otherwise creates a new one. */
struct logger * FORMAT_ATTR(printf, 1, 2)
logger_mgr_get(const char *format, ...) {
    char name[LOGGER_NAME_MAX_LEN];

    va_list args;
    va_start(args, format);
    vsnprintf(name, LOGGER_NAME_MAX_LEN, format, args);
    va_end(args);

    pthread_mutex_lock(logger_mgr_mutex);

    struct logger *l;
    HASH_FIND_STR(loggers, name, l);
    if (l == NULL) {
        l = logger_new(name);
        pthread_mutex_lock(l->mutex);
        HASH_ADD_STR(loggers, name, l);
        pthread_mutex_unlock(l->mutex);
    }

    pthread_mutex_unlock(logger_mgr_mutex);

    assert(l != NULL);
    return l;
}

/* Finds if a same rule exists.
 * NOTE must be called with mutex locked. */
static struct logger_rule *
find_existing_rule(char *prefix, size_t prefix_len, bool exact) {
    struct logger_rule *rule;
    LL_FOREACH(rules->head, rule) {
        if ((strncmp(rule->prefix, prefix, prefix_len) == 0) && (rule->exact == exact)) {
            return rule;
        }
    }

    return NULL;
}

/* Applies rules to all loggers.
 * NOTE must be called with mutex locked. */
static void
apply_rules() {
    struct logger *logger, *next;
    struct logger_rule *rule;
    HASH_ITER(hh, loggers, logger, next) {
        pthread_mutex_lock(logger->mutex);
        rule = find_matching_rule(logger->name);
        assert(rule != NULL);

        logger->level = rule->level;
        logger->facility = rule->facility;
        pthread_mutex_unlock(logger->mutex);
    }
}

/* Adds a new rule to the logger manager. */
void
logger_mgr_add_rule(char *name, enum logger_level level, enum logger_facility facility) {
    pthread_mutex_lock(logger_mgr_mutex);

    // check if name has a *
    char *star = strchr(name, '*');

    struct logger_rule *rule;
    if (star == NULL) {
        rule = find_existing_rule(name, strlen(name), true);
    } else {
        rule = find_existing_rule(name, (star - name), false);
    }

    if (rule != NULL) {
        rule->level = level;
        rule->facility = facility;
    } else {
        // create new rule
        rule = malloc(sizeof(struct logger_rule));
        if (star == NULL) {
            rule->prefix = strdup(name);
            rule->exact = true;
        } else {
            rule->prefix = strncpy(malloc(star - name + 1), name, star - name);
            rule->prefix[star - name] = '\0';
            rule->exact = false;
        }
        rule->level = level;
        rule->facility = facility;

        LL_APPEND(rules->head, rule);
    }

    apply_rules();

    pthread_mutex_unlock(logger_mgr_mutex);
}

/* Sets the default rule in the logger manager. */
void
logger_mgr_default_rule(enum logger_level level, enum logger_facility facility) {
    logger_mgr_add_rule("*", level, facility);
}
