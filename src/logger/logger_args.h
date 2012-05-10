/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef LOGGER_ARGS_H
#define LOGGER_ARGS_H 1

#define LOGGER_ARGS_NAME  "verbose"
#define LOGGER_ARGS_KEY   'v'
#define LOGGER_ARGS_ARG   "LOGGERS"
#define LOGGER_ARGS_FLAGS OPTION_ARG_OPTIONAL
#define LOGGER_ARGS_DOC \
    "Sets the verbosity level for loggers. "                                         \
    "Without arguments, sets default level to DEBUG. "                               \
    "Otherwise requires a comma separated list of logger settings. "                 \
    "A log level in itself will set the default logging level to that level. "       \
    "A NAME:LVL element will set the logging level for the loggers with that name. " \
    "A NAME:LVL:FAC element will also set the facility to be used by the logger. "   \
    "Name can end in an asterix, which will prefix match all logger names."          \
    "Supported levels: EMERG,ALERT,CRIT,ERR,WARN,NOTICE,INFO,DEBUG. "                \
    "Supported facilites: STDOUT. "                                                  \
    "Without these calls, the default log level will be WARN. "                      \
    "Example: dp*:WARN,pdrv:DEBUG:STDOUT,ERR."

#define LOGGER_ARGS                                                  \
    {.name = LOGGER_ARGS_NAME, .key =   LOGGER_ARGS_KEY,             \
     .arg =  LOGGER_ARGS_ARG,  .flags = LOGGER_ARGS_FLAGS,           \
     .doc  = LOGGER_ARGS_DOC}



struct argp_state;

void *
logger_args_new();

void
logger_args_free(void *args);

void
logger_args_parse(void *args_, char *arg, struct argp_state *state);

#endif /* LOGGER_ARGS_H */
