/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef DP_CTRL_H
#define DP_CTRL_H 1

#include "lib/openflow.h"

struct dp_msg;
struct ofl_msg_header;

void
dp_ctrl_recv_msg(struct dp_loop *dp_loop, struct dp_msg *msg);

void
dp_ctrl_send_msg(struct dp_loop *dp_loop, size_t conn_id, of_xid_t xid, struct ofl_msg_header *msg);

#endif /* DP_CTRL_H */
