/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */


#ifndef _CTRL_CONN_H_
#define _CTRL_CONN_H_ 1

struct conn;
struct ctrl_loop;

void
ctrl_conn_add(struct ctrl_loop *ctrl_loop, const char *trans, const char *host, const char *port);

void
ctrl_conn_idle(struct conn *conn);

size_t
ctrl_conn_read(struct conn *conn, uint8_t *buf, size_t buf_size);

void
ctrl_conn_send_msg(struct conn *conn, of_xid_t xid, struct ofl_msg_header *msg);

size_t
ctrl_conn_msg_len(uint8_t *buf, size_t buf_size);


#endif /* _CTRL_CONN_H_ */
