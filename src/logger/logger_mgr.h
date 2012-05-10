/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef LOGGER_MGR_H
#define LOGGER_MGR_H 1

#include "lib/compiler.h"

enum logger_level;
enum logger_facility;
struct logger;

void
logger_mgr_init();

void
logger_mgr_args(void *args);

struct logger *
logger_mgr_get(const char *format, ...) FORMAT_ATTR(printf, 1, 2);

void
logger_mgr_add_rule(char *name, enum logger_level level, enum logger_facility facility);

void
logger_mgr_default_rule(enum logger_level level, enum logger_facility facility);

#endif /* LOGGER_MGR_H */
