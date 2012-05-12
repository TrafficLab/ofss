/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef INFO_H
#define INFO_H 1

#define INFO_ARGS_NAME  "info"
#define INFO_ARGS_KEY   'i'
#define INFO_ARGS_ARG   "ARGS"
#define INFO_ARGS_FLAGS OPTION_ARG_OPTIONAL
#define INFO_ARGS_DOC \
     "Dumps various system information to screen.\n"

#define INFO_ARGS                                          \
    {.name = INFO_ARGS_NAME, .key =   INFO_ARGS_KEY,       \
     .arg  = INFO_ARGS_ARG,  .flags = INFO_ARGS_FLAGS,     \
     .doc  = INFO_ARGS_DOC,  .group = 0}

void
info();

#endif /* INFO_H */
