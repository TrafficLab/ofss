/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ev.h>
#include <pthread.h>
#include <uthash/utlist.h>
#include "control/ctrl.h"
#include "lib/openflow.h"
#include "lib/compiler.h"
#include "lib/message_box.h"
#include "lib/pkt_buf.h"
#include "lib/thread_id.h"
#include "lib/util.h"
#include "lib/logger_names.h"
#include "logger/logger.h"
#include "logger/logger_mgr.h"
#include "port/port_drv.h"
#include "port/port_drv_mgr.h"
#include "dp.h"
#include "dp_bufs.h"
#include "dp_ctrl.h"
#include "dp_int.h"
#include "pipeline_packet.h"
#include "flow_table.h"
#include "group_table.h"
#include "pipeline.h"

/*
 * Provides DP related functions. These are used by the manager
 * to contact the given DPs, and by the DP functions internally
 * to access data within the DP structures.
 */

#define MFR_DESC     "TrafficLab, Ericsson Research, Hungary"
#define HW_DESC      "OpenFlow Software Switch"
#define SW_DESC      "OpenFlow 1.1"
#define DP_DESC      "OpenFlow Software Switch"
#define SERIAL_NUM   __DATE__" "__TIME__

#define TIMER_PERIOD 1.0


static void *event_loop(void *dp_loop_);

static void event_loop_periodic_cb(struct ev_loop *loop, ev_timer *w, int revents);

static bool process_pkt(void *dp_port_, struct list_node *pkt_buf_);
static bool process_msg(void *dp_loop_, struct list_node *msg_);


/* Creates and spawns a new DP.*/
struct dp * MALLOC_ATTR
dp_new(size_t uid, of_dpid_t dpid) {
    struct dp *dp = malloc(sizeof(struct dp));
    dp->uid = uid;
    dp->dpid = dpid; // already checked by dp_mgr
    dp->logger = logger_mgr_get(LOGGER_NAME_DP_IF, uid);

    dp->ports_lock = malloc(sizeof(pthread_rwlock_t));
    pthread_rwlock_init(dp->ports_lock, NULL);
    size_t i;
    for (i=0; i <= MAX_PORTS; i++) {
        dp->ports[i] = NULL;
    }
    dp->ports_num = 0;

    struct dp_loop *dp_loop = malloc(sizeof(struct dp_loop));
    dp_loop->uid = uid;
    dp_loop->dpid = dpid;
    dp_loop->logger = logger_mgr_get(LOGGER_NAME_DP, uid);
    dp_loop->logger_ctrl = logger_mgr_get(LOGGER_NAME_DP_CTRL, uid);
    dp_loop->logger_pl = logger_mgr_get(LOGGER_NAME_DP_PL, uid);
    dp_loop->logger_pkt = logger_mgr_get(LOGGER_NAME_DP_PKT, uid);

    dp_loop->bufs = dp_bufs_new(dp_loop);

    for (i=0; i < TABLES_NUM; i++) {
        dp_loop->tables[i] = flow_table_new(dp_loop, i);
    }
    dp_loop->groups = group_table_new(dp_loop);
    //TODO check for NULLs

    dp_loop->of_conf.flags         = OFPC_FRAG_NORMAL;
    dp_loop->of_conf.miss_send_len = OFP_DEFAULT_MISS_SEND_LEN;


    dp_loop->desc = malloc(sizeof(struct dp_desc));
    memset(dp_loop->desc, 0, sizeof(struct dp_desc));
    strncpy(dp_loop->desc->mfr_desc, MFR_DESC, DESC_STR_LEN);
    strncpy(dp_loop->desc->hw_desc, HW_DESC, DESC_STR_LEN);
    strncpy(dp_loop->desc->sw_desc, SW_DESC, DESC_STR_LEN);
    strncpy(dp_loop->desc->dp_desc, DP_DESC, DESC_STR_LEN);
    strncpy(dp_loop->desc->serial_num, SERIAL_NUM, SERIAL_NUM_LEN);

    dp->dp_loop = dp_loop;
    dp_loop->dp = dp;

    dp->ctrl = ctrl_new(dp);
    if (dp->ctrl == NULL) {
        logger_log(dp->logger, LOG_WARN, "Error creating control for datapath %"PRIx64".", dpid);
        //TODO: free structures
        return NULL;
    }

    dp_loop->ctrl = dp->ctrl;

    dp->thread = malloc(sizeof(pthread_t));
    dp->loop = ev_loop_new(0/*flags*/);
    dp_loop->loop = dp->loop;

    dp->msg_mbox = mbox_new(dp->loop, dp_loop, process_msg);

    ev_set_userdata(dp->loop, (void *)dp_loop);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    int rc;
    if ((rc = pthread_create(dp->thread, &attr, event_loop, (void *)dp_loop)) != 0) {
        logger_log(dp->logger, LOG_ERR, "Unable to create thread (%d).", rc);
        free(dp_loop->desc);
        //TODO: free structures
        return NULL;
    }

    dp_loop->periodic_timer = malloc(sizeof(struct ev_timer));

    ev_timer_init(dp_loop->periodic_timer, event_loop_periodic_cb, TIMER_PERIOD, TIMER_PERIOD);
    dp_loop->periodic_timer->data = dp_loop;
    ev_timer_start(dp_loop->loop, dp_loop->periodic_timer);

    logger_log(dp->logger, LOG_INFO, "DP created (dpid=%"PRIx64").", dp->dpid);

    return dp;
}

/* Sends a packtet to the DP's thread. */
void
dp_recv_pkt(struct dp *dp, of_port_no_t port_no, struct pkt_buf *pkt_buf) {
    pthread_rwlock_rdlock(dp->ports_lock);
    struct dp_port *dp_port = dp->ports[port_no];
    pthread_rwlock_unlock(dp->ports_lock);

    if (dp_port != NULL) {
        pthread_rwlock_rdlock(dp_port->rwlock);
        bool enabled = ((dp_port->of_config & OFPPC_NO_RECV) == 0);
        pthread_rwlock_unlock(dp_port->rwlock);

        if (enabled) {
            mbox_send(dp_port->pkt_mbox, (struct list_node *)pkt_buf);
        } else {
            //TODO log (should not have received)
        }
    } else {
        logger_log(dp->logger, LOG_WARN, "packet received on non-existing port");
    }

}

/* Sends a message to the DP's thread. */
void
dp_recv_msg(struct dp *dp, size_t conn_id, of_xid_t xid, struct ofl_msg_header *msg, uint8_t *of_msg, size_t of_msg_len) {
    struct dp_msg *message = malloc(sizeof(struct dp_msg));
    message->conn_id = conn_id;
    message->xid = xid;
    message->msg = msg;
    message->ofp_msg_len = MIN(of_msg_len, 64);
    message->ofp_msg     = memcpy(malloc(message->ofp_msg_len), of_msg, message->ofp_msg_len);

    mbox_send(dp->msg_mbox, (struct list_node *)message);
}

/* Finds the next lowest unused port number on the DP. */
static of_port_no_t
next_port_no(struct dp *dp) {
    size_t i;
    for (i = 1; i < MAX_PORTS; i++) {
        if (dp->ports[i] == NULL) {
            return i;
        }
    }

    assert(false); // only called if there is an available port
    return OF_NO_PORT;
}

/* Requests the DP to add a port. */
void
dp_add_port(struct dp *dp, of_port_no_t dp_port_no UNUSED_ATTR, const char *driver_name, const char *port_name) {
    pthread_rwlock_wrlock(dp->ports_lock);

    if (dp->ports_num == MAX_PORTS) {
        pthread_rwlock_unlock(dp->ports_lock);
        logger_log(dp->logger, LOG_WARN, "Cannot add more ports.");
        return;
    }

    if (dp_port_no != OF_NO_PORT) {
        if (dp_port_no >= MAX_PORTS) {
            pthread_rwlock_unlock(dp->ports_lock);
            logger_log(dp->logger, LOG_WARN, "Invalid port number.");
            return;
        }
        if (dp->ports[dp_port_no] != NULL) {
            pthread_rwlock_unlock(dp->ports_lock);
            logger_log(dp->logger, LOG_WARN, "Port number already in use.");
            return;
        }

    } else {
        dp_port_no = next_port_no(dp);
    }

    struct port_drv *drv = port_drv_mgr_get(driver_name);
    if (drv == NULL) {
        pthread_rwlock_unlock(dp->ports_lock);
        logger_log(dp->logger, LOG_WARN, "Cannot find requested driver %s.", STR_DEF(driver_name, ""));
        return;
    }

    ssize_t drv_port_no = port_drv_get_port(drv, port_name);
    if (drv_port_no == -1) {
        pthread_rwlock_unlock(dp->ports_lock);
        logger_log(dp->logger, LOG_WARN, "Cannot find requested port %s:%s.", STR_DEF(driver_name, ""), port_name);
        return;
    }

    if (!port_drv_assign_dp_port(drv, drv_port_no, dp->uid, dp_port_no)) {
        pthread_rwlock_unlock(dp->ports_lock);
        logger_log(dp->logger, LOG_WARN, "Cannot assign dp port to %s:%s.", STR_DEF(driver_name, ""), port_name);
        return;
    }

    struct dp_port *dp_port = malloc(sizeof(struct dp_port));
    dp_port->dp = dp;
    dp_port->dp_loop = dp->dp_loop;
    dp_port->dp_port_no = dp_port_no;
    dp_port->drv = drv;
    dp_port->drv_port_no = drv_port_no;
    dp_port->pkt_mbox = mbox_new(dp->loop, dp_port, process_pkt);
    dp_port->of_config = 0; // TODO; what is the default ?!
    dp_port->rwlock = malloc(sizeof(pthread_rwlock_t));
    pthread_rwlock_init(dp_port->rwlock, NULL);

    dp->ports[dp_port_no] = dp_port;
    dp->ports_num++;

    logger_log(dp->logger, LOG_INFO, "Assigned port %s:%s as DP port %u.", STR_DEF(driver_name, ""), port_name, dp_port_no);
    pthread_rwlock_unlock(dp->ports_lock);
}

/* Requests the DP to add a controller. */
void
dp_add_ctrl(struct dp *dp, const char *trans, const char *host, const char *port) {
    ctrl_add_conn(dp->ctrl, trans, host, port);
}


/* Requests the current timestamp from the DP in the DP's thread. */
ev_tstamp
dp_loop_now(struct dp_loop *dp_loop) {
    return ev_now(dp_loop->loop);
}

/* Returns the DPID of the DP. */
of_dpid_t
dp_get_dpid(const struct dp *dp) {
    return dp->dpid;
}

/* Returns the UID of the DP. */
size_t
dp_get_uid(const struct dp *dp) {
    return dp->uid;
}

/* Returns the DPID of the DP in the DP's thread. */
of_dpid_t
dp_loop_get_dpid(const struct dp_loop *dp_loop) {
    return dp_loop->dpid;
}

/* Returns the unique ID of the DP in the DP's thread. */
size_t
dp_loop_get_uid(const struct dp_loop *dp_loop) {
    return dp_loop->uid;
}


/* Used by the pipeline to send a packet out on one of its ports. */
static void
send_to_port(struct dp_port *dp_port, struct pl_pkt *pl_pkt) {
    //TODO: check port stats
    pthread_rwlock_rdlock(dp_port->rwlock);
    if ((dp_port->of_config & OFPPC_NO_FWD) != 0) {
        pthread_rwlock_unlock(dp_port->rwlock);
        return;
    }

    struct port_drv *drv = dp_port->drv;
    size_t drv_port_no = dp_port->drv_port_no;
    pthread_rwlock_unlock(dp_port->rwlock);
    port_drv_send_pkt(drv, drv_port_no, pkt_buf_clone(pl_pkt->pkt, NULL));
}


/* Used by the pipeline to send a packet to the controller.
 * NOTE: for now this always copies the packet, which is probably inefficient. */
void
dp_pl_pkt_to_ctrl(struct dp_loop *dp_loop, uint16_t max_len, struct pl_pkt *pl_pkt, uint8_t reason) {
    struct dp *dp = dp_loop->dp;
    pthread_rwlock_rdlock(dp->ports_lock);
    struct dp_port *dp_port = dp->ports[pl_pkt->in_port];
    pthread_rwlock_unlock(dp->ports_lock);

    bool send;
    if (dp_port == NULL) {
        logger_log(dp_loop->logger, LOG_WARN, "Packet received on non-existing port (%u).", pl_pkt->in_port);
        send = true;
    } else {
        pthread_rwlock_rdlock(dp_port->rwlock);
        send = ((dp_port->of_config & OFPPC_NO_PACKET_IN) == 0);
        pthread_rwlock_unlock(dp_port->rwlock);
    }

    if (send) {
        size_t copy_len = MIN(max_len, MIN(dp_loop->of_conf.miss_send_len, pl_pkt->pkt->data_len));
        uint8_t *copy = memcpy(malloc(copy_len), pl_pkt->pkt->data, copy_len);
        of_bufferid_t buffer_id = dp_bufs_put_raw(dp_loop->bufs, copy, copy_len);

        struct ofl_msg_packet_in *msg = malloc(sizeof(struct ofl_msg_packet_in));
        msg->header.type = OFPT_PACKET_IN;
        msg->buffer_id   = buffer_id;
        msg->in_port     = pl_pkt->in_port;
        msg->in_phy_port = pl_pkt->in_port;
        msg->total_len   = pl_pkt->pkt->data_len;
        msg->reason      = reason;
        msg->table_id    = pl_pkt->table_id;
        msg->data_length = copy_len;
        msg->data        = buffer_id == OF_NO_BUFFER ? copy : memcpy(malloc(copy_len), pl_pkt->pkt->data, copy_len);

        ctrl_send_msg(dp_loop->ctrl, CTRL_CONN_ALL, 0/*XID*/, (struct ofl_msg_header *)msg);
    }
    //TODO else and cleanup?
}

/* Used by the pipeline to send a packet to port(s).
 * NOTE: for now this always copies the packet, which is probably inefficient. */
void
dp_pl_pkt_to_port(struct dp_loop *dp_loop, of_port_no_t port, uint16_t max_len, struct pl_pkt *pl_pkt) {
    switch (port) {
        case OFPP_CONTROLLER: {
            dp_pl_pkt_to_ctrl(dp_loop, max_len, pl_pkt, OFPR_ACTION);
            return;
        }
        case OFPP_TABLE: {
            if (pl_pkt->pkt_out) {
                struct pl_pkt *clone = pl_pkt_clone(pl_pkt);
                clone->pkt_out = false; // avoid loops
                pipeline_process(dp_loop, clone);
            } else {
                logger_log(dp_loop->logger, LOG_WARN, "Trying to sent to OFPP_TABLE on non-packet-out packet.");
            }
            return;
        }
        case OFPP_ALL: {
            pthread_rwlock_rdlock(dp_loop->dp->ports_lock);
            size_t i = 0;
            for (i=0; i < MAX_PORTS; i++) {
                struct dp_port *dp_port = dp_loop->dp->ports[i];
                if (dp_port != NULL && dp_port->dp_port_no != pl_pkt->in_port) {
                    send_to_port(dp_port, pl_pkt);
                }
            }
            pthread_rwlock_unlock(dp_loop->dp->ports_lock);
            return;
        }
        case OFPP_IN_PORT:
        default: {
            if (pl_pkt->in_port == port) {
                logger_log(dp_loop->logger, LOG_WARN, "Trying to send packet on input port %d.", pl_pkt->in_port);
                return;
            }
            of_port_no_t out_port = (port == OFPP_IN_PORT) ? pl_pkt->in_port : port;

            struct dp *dp = dp_loop->dp;
            pthread_rwlock_rdlock(dp->ports_lock);
            struct dp_port *dp_port = dp->ports[out_port];
            pthread_rwlock_unlock(dp->ports_lock);

            if (dp_port != NULL) {
                send_to_port(dp_port, pl_pkt);
            } else {
                logger_log(dp_loop->logger, LOG_WARN, "Trying to send packet on unknown port %d.", pl_pkt->in_port);
            }
            return;
        }
    }
}


/* Requests the pipeline to add a flow ref to a given group.
 * Used by flow tables to communicate to group tables.*/
void
dp_pl_group_add_flow_ref(struct dp_loop *dp_loop, of_groupid_t group_id, uint32_t flow_ref) {
    group_table_add_flow_ref(dp_loop->groups, group_id, flow_ref);
}

/* Requests the pipeline to remove a flow ref from a given group.
 * Used by flow tables to communicate to group tables.*/
void
dp_pl_group_del_flow_ref(struct dp_loop *dp_loop, of_groupid_t group_id, uint32_t flow_ref) {
    group_table_del_flow_ref(dp_loop->groups, group_id, flow_ref);
}

/* Requests the pipeline to remove a flow based on its ref.
 * Used by group tables to communicate to flow tables.*/
void
dp_pl_flow_remove_by_ref(struct dp_loop *dp_loop, uint32_t flow_ref) {
    flow_table_remove_by_ref(dp_loop->tables[(flow_ref >> 24)], flow_ref);
}

/* Spawns the event loop of the DP thread. */
static void *
event_loop(void *dp_loop_) {
    assert(dp_loop_ != NULL);
    struct dp_loop *dp_loop = (struct dp_loop *)dp_loop_;

    thread_id_set();

    logger_log(dp_loop->logger, LOG_INFO, "Thread started for DP pipeline (dpid=%"PRIx64").", dp_loop->dpid);

    ev_ref(dp_loop->loop); //makes sure an empty loop stays alive
    ev_run(dp_loop->loop, 0/*flags*/);

    logger_log(dp_loop->logger, LOG_ERR, "Loop exited.");

    pthread_exit(NULL);
    return NULL;
}

/* Called periodically be the timeout timer. */
static void
event_loop_periodic_cb(struct ev_loop *loop UNUSED_ATTR, ev_timer *w, int revents UNUSED_ATTR) {
   struct dp_loop *dp_loop = (struct dp_loop*)(w->data);

    ev_tstamp now = dp_loop_now(dp_loop);

    size_t i;
    for(i = 0; i < TABLES_NUM; i++) {
        flow_table_timeout(dp_loop->tables[i], now);
    }

}

/* Called when a packet is received from the sender functions. */
static bool
process_pkt(void *dp_port_, struct list_node *pkt_buf_) {
    struct dp_port *dp_port = (struct dp_port *)dp_port_;
    struct pkt_buf *pkt_buf = (struct pkt_buf *)pkt_buf_;

    pipeline_process(dp_port->dp_loop, pl_pkt_new(pkt_buf, false/*pkt_out*/, dp_port->dp_port_no));
    return true;
}

/* Called when a message is received from the sender functions. */
static bool
process_msg(void *dp_loop_, struct list_node *msg_) {
    struct dp_loop *dp_loop = (struct dp_loop *)dp_loop_;
    struct dp_msg *msg = (struct dp_msg *)msg_;
    logger_log(dp_loop->logger, LOG_DEBUG, "Received msg request.");
    dp_ctrl_recv_msg(dp_loop, msg);
    free(msg);

    return true;
}
