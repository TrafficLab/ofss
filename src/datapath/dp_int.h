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
 * Common internal structures for the DP.
 */

#ifndef DP_INT_H
#define DP_INT_H 1


#include <ev.h>
#include <pthread.h>
#include <openflow/openflow.h>
#include "lib/message_box.h"
#include "oflib/ofl_structs.h"

struct pl_pkt;

#define TABLES_NUM   255
#define MAX_PORTS 16

struct dp_msg {
    struct list_node list;

    size_t                  conn_id;
    of_xid_t                xid;
    struct ofl_msg_header  *msg;
    uint8_t                *ofp_msg;     // keep for error messages
    size_t                  ofp_msg_len; // MAX 64
};

// dp_port is now const, no need for locking
struct dp_port {
    struct dp         *dp;
    struct dp_loop    *dp_loop;
    of_port_no_t       dp_port_no;

    struct port_drv   *drv;
    size_t             drv_port_no;

    struct mbox       *pkt_mbox;

    uint32_t           of_config;

    pthread_rwlock_t  *rwlock;
};

struct dp {
    size_t      uid;
    of_dpid_t   dpid;
    struct logger      *logger;

    struct ctrl         *ctrl;

    struct dp_port   *ports[MAX_PORTS];
    size_t            ports_num;
    pthread_rwlock_t *ports_lock;

    pthread_t        *thread;
    struct ev_loop   *loop;

    struct mbox      *msg_mbox;

    struct dp_loop   *dp_loop;
};

struct dp_desc;


struct dp_loop {
    size_t      uid;
    of_dpid_t   dpid;
    struct logger      *logger;
    struct logger      *logger_ctrl;
    struct logger      *logger_pl;
    struct logger      *logger_pkt;

    struct ctrl         *ctrl;

    struct dp_bufs      *bufs;

    struct flow_table   *tables[TABLES_NUM];
    struct group_table  *groups;
    struct ofl_config    of_conf;

    struct dp_desc      *desc;

    struct ev_loop      *loop;
    ev_timer            *periodic_timer;

    struct dp           *dp;
};

struct dp_desc {
    char   mfr_desc[DESC_STR_LEN];
    char   hw_desc[DESC_STR_LEN];
    char   sw_desc[DESC_STR_LEN];
    char   dp_desc[DESC_STR_LEN];
    char   serial_num[SERIAL_NUM_LEN];
};


void
dp_pl_pkt_to_ctrl(struct dp_loop *dp_loop, uint16_t max_len, struct pl_pkt *pl_pkt, uint8_t reason);

void
dp_pl_pkt_to_port(struct dp_loop *dp_loop, of_port_no_t port, uint16_t max_len, struct pl_pkt *pl_pkt);


void
dp_pl_group_add_flow_ref(struct dp_loop *dp_loop, of_groupid_t group_id, uint32_t flow_ref);

void
dp_pl_group_del_flow_ref(struct dp_loop *dp_loop, of_groupid_t group_id, uint32_t flow_ref);

void
dp_pl_flow_remove_by_ref(struct dp_loop *dp_loop, uint32_t flow_ref);


#endif /* DP_INT_H */
