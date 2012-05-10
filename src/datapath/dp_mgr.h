/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef DP_MGR_H
#define DP_MGR_H 1

#include "lib/openflow.h"

struct pkt_buf;
struct ofl_msg_header;


void
dp_mgr_init();

ssize_t
dp_mgr_create_dp(of_dpid_t dpid);

void
dp_mgr_dp_recv_pkt(size_t dp_uid, of_port_no_t port_no, struct pkt_buf *pkt_buf);

void
dp_mgr_dp_recv_msg(size_t dp_uid, size_t conn_id, of_xid_t xid, struct ofl_msg_header *msg, uint8_t *of_msg, size_t of_msg_len);


void
dp_mgr_dp_add_port(size_t dp_uid, of_port_no_t port_no, const char *driver, const char *port);

void
dp_mgr_dp_add_ctrl(size_t dp_uid, const char *trans, const char *host, const char *port);

#endif /* DP_MGR_H */
