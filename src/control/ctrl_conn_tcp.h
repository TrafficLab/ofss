/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */


#ifndef CTRL_CONN_TCP_H
#define CTRL_CONN_TCP_H 1


struct ctrl;
struct conn;
struct conn_tcp;


struct conn_tcp *
ctrl_conn_tcp_new(struct conn *conn, const char *host, const char *port_);

void
ctrl_conn_tcp_send(struct conn_tcp *tcp, uint8_t *buf, size_t buf_size);

#endif /* CTRL_CONN_TCP_H */
