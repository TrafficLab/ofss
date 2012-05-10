/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef DP_H
#define DP_H 1

#include <ev.h>
#include "lib/openflow.h"

struct dp;
struct dp_loop;


struct pkt_buf;
struct ofl_msg_header;


struct dp *
dp_new(size_t uid, of_dpid_t dpid);

void
dp_recv_pkt(struct dp *dp, of_port_no_t port_no, struct pkt_buf *pkt_buf);

void
dp_recv_msg(struct dp *dp, size_t conn_id, of_xid_t xid, struct ofl_msg_header *msg, uint8_t *of_msg, size_t of_msg_len);


void
dp_add_port(struct dp *dp, of_port_no_t port_no, const char *driver_name, const char *port_name);

void
dp_add_ctrl(struct dp *dp, const char *trans, const char *host, const char *port);


of_dpid_t
dp_get_dpid(const struct dp *dp);

size_t
dp_get_uid(const struct dp *dp);

of_dpid_t
dp_loop_get_dpid(const struct dp_loop *dp_loop);

size_t
dp_loop_get_uid(const struct dp_loop *dp_loop);

ev_tstamp
dp_loop_now(struct dp_loop *dp_loop);


#endif /* DP_H */
