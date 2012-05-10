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
 * Common internal structures for configuration.
 */

#ifndef CONF_INT_H
#define CONF_INT_H 1

#include "lib/openflow.h"

/* DP related config arguments. */
struct dp_args {
    of_dpid_t   dpid;
};

/* Port related config arguments. */
struct port_arg {
    char  *driver_name;
    char  *port_name;
    struct port_arg *next;
};

/* Controller related config arguments. */
struct ctrl_arg {
    char  *transport;
    char  *host;
    char  *port;
    struct ctrl_arg *next;
};

/* Config arguments. */
struct conf_args {
    struct dp_args   *dp;
    struct ctrl_arg  *ctrls;
    struct port_arg  *ports;
};

#endif /* CONF_INT_H */
