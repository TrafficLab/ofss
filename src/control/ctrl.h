/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef CTRL_H
#define CTRL_H 1


#include <stddef.h>
#include "lib/openflow.h"

struct ctrl;
struct dp;
struct ofl_msg_header;

#define CTRL_CONN_ALL  0

struct ctrl *
ctrl_new(struct dp *dp);

void
ctrl_add_conn(struct ctrl *ctrl, const char *trans, const char *host, const char *port);

void
ctrl_send_msg(struct ctrl *ctrl, size_t conn_id, of_xid_t xid, struct ofl_msg_header *msg);


#endif /* CTRL_H */
