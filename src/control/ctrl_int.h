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
 * Common internal structures for controller handling.
 */

#ifndef CTRL_INT_H
#define CTRL_INT_H 1

#define MAX_CONNS 16

#include "lib/message_box.h"
#include "lib/openflow.h"

struct logger;
struct conn;

enum ctrl_cmd_type {
    CMD_ADD_CONN
};

struct ctrl_cmd {
    struct list_node list;

    enum ctrl_cmd_type type;
    union {
        struct {
            char *trans;
            char *host;
            char *port;
        } add_conn;
    };
};

struct ctrl_msg {
    struct list_node list;

    size_t conn_id;
    of_xid_t xid;
    struct ofl_msg_header *msg;
};

struct ctrl {
    struct dp         *dp;
    struct logger     *logger;

    struct mbox   *cmd_mbox;
    struct mbox   *msg_mbox;

    pthread_t         *thread;
    struct ev_loop    *loop;


    struct ctrl_loop  *ctrl_loop;
};


struct ctrl_loop {
    struct dp        *dp;
    struct logger    *logger;

    struct conn      *conns[MAX_CONNS];
    size_t            conns_num;

    struct ev_loop   *loop;

    struct ctrl      *ctrl;
};


enum conn_trans {
    CONN_TCP
};

struct conn {
    struct ctrl_loop  *ctrl_loop;
    struct logger     *logger;
    size_t             id;
    enum conn_trans    trans;
    void              *private;
};


#endif /* CTRL_INT_H */
