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
 * Handles the connections of a datapath to OpenFlow controllers.
 * One controller thread is spawned for each DP thread..
 */

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <ev.h>
#include <uthash/utlist.h>
#include "datapath/dp.h"
#include "lib/compiler.h"
#include "lib/message_box.h"
#include "lib/thread_id.h"
#include "lib/util.h"
#include "lib/logger_names.h"
#include "logger/logger.h"
#include "logger/logger_mgr.h"
#include "oflib/ofl_messages.h"
#include "ctrl.h"
#include "ctrl_conn.h"
#include "ctrl_int.h"


static void *event_loop(void *ctrl_loop_);
static bool process_cmd(void *ctrl_loop_, struct list_node *cmd_);
static bool process_msg(void *ctrl_loop_, struct list_node *msg_);

/* Creates and spawns a new controller handler. */
struct ctrl * MALLOC_ATTR
ctrl_new(struct dp *dp) {
    struct ctrl *ctrl = malloc(sizeof(struct ctrl));
    ctrl->dp = dp;
    ctrl->logger = logger_mgr_get(LOGGER_NAME_CTRL, dp_get_uid(dp));

    struct ctrl_loop *ctrl_loop = malloc(sizeof(struct ctrl_loop));
    ctrl_loop->dp = dp;
    ctrl_loop->logger = logger_mgr_get(LOGGER_NAME_CTRL_IF, dp_get_uid(dp));

    size_t i;
    for (i=0; i<MAX_CONNS; i++) {
        ctrl_loop->conns[i] = NULL;
    }
    ctrl_loop->conns_num = 1; // "0" is used for broadcast

    ctrl->ctrl_loop = ctrl_loop;
    ctrl_loop->ctrl = ctrl;

    ctrl->thread = malloc(sizeof(pthread_t));
    ctrl->loop   = ev_loop_new(0/*flags*/);
    ctrl_loop->loop = ctrl->loop;

    ctrl->cmd_mbox = mbox_new(ctrl->loop, ctrl_loop, process_cmd);
    ctrl->msg_mbox = mbox_new(ctrl->loop, ctrl_loop, process_msg);

    ev_set_userdata(ctrl->loop, (void *)ctrl_loop);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    int rc;
    if ((rc = pthread_create(ctrl->thread, &attr, event_loop, (void *)ctrl_loop)) != 0) {
        logger_log(ctrl->logger, LOG_ERR, "Unable to create thread (%d).", rc);
        //TODO free structures
        return NULL;
    }

    logger_log(ctrl->logger, LOG_INFO, "Initialized.");

    return ctrl;
}

/* Instructs the controller handler to add a new connection.
 * Can be called from any thread; will send an async message to the connection thread. */
void
ctrl_add_conn(struct ctrl *ctrl, const char *trans, const char *host, const char *port) {
    assert(host != NULL);
    struct ctrl_cmd *cmd = malloc(sizeof(struct ctrl_cmd));
    cmd->type = CMD_ADD_CONN;
    cmd->add_conn.trans = (trans == NULL) ? NULL : strdup(trans);
    cmd->add_conn.host = strdup(host);
    cmd->add_conn.port = (port == NULL) ? NULL : strdup(port);

    logger_log(ctrl->logger, LOG_DEBUG, "Sending request for connection: %s:%s:%s.",
                                        STR_DEF(trans, "DEF"), host, STR_DEF(port, "DEF"));

    mbox_send(ctrl->cmd_mbox, (struct list_node *)cmd);
}

/* Instructs the controller handler to send a message to the controller(s).
 * Can be called from any thread; will send an async message to the connection thread. */
void
ctrl_send_msg(struct ctrl *ctrl, size_t conn_id, of_xid_t xid, struct ofl_msg_header *msg) {
    struct ctrl_msg *message = malloc(sizeof(struct ctrl_msg));
    message->conn_id = conn_id;
    message->xid     = xid;
    message->msg     = msg;

    logger_log(ctrl->logger, LOG_DEBUG, "Sending request for message.");

    mbox_send(ctrl->msg_mbox, (struct list_node *)message);
}


/* Starts the event loop attached to the controller thread. */
static void *
event_loop(void *ctrl_loop_) {
    assert(ctrl_loop_ != NULL);
    struct ctrl_loop *ctrl_loop = (struct ctrl_loop *)ctrl_loop_;

    thread_id_set();

    logger_log(ctrl_loop->logger, LOG_INFO, "Thread started for DP control.");

    ev_ref(ctrl_loop->loop); //makes sure an empty loop stays alive
    ev_run(ctrl_loop->loop, 0/*flags*/);

    logger_log(ctrl_loop->logger, LOG_ERR, "Loop exited.");

    pthread_exit(NULL);
    return NULL;
}

/* Processes commands received from other threads via the appropriate functions. */
static bool process_cmd(void *ctrl_loop_, struct list_node *cmd_) {
    struct ctrl_loop *ctrl_loop = (struct ctrl_loop *)ctrl_loop_;
    struct ctrl_cmd *cmd = (struct ctrl_cmd *)cmd_;

    switch(cmd->type) {
        case CMD_ADD_CONN: {
            logger_log(ctrl_loop->logger, LOG_DEBUG, "Received add conn request.");
            ctrl_conn_add(ctrl_loop, cmd->add_conn.trans, cmd->add_conn.host, cmd->add_conn.port);
            break;
        }
    }
    free(cmd->add_conn.trans);
    free(cmd->add_conn.host);
    free(cmd->add_conn.port);
    free(cmd);

    return true;
}

/* Sends OpenFlow messages received from other threads via the appropriate functions.
 * Primarily used by DP to send messages to the controllers. */
static bool process_msg(void *ctrl_loop_, struct list_node *msg_) {
    struct ctrl_loop *ctrl_loop = (struct ctrl_loop *)ctrl_loop_;
    struct ctrl_msg *msg = (struct ctrl_msg *)msg_;

    if (msg->conn_id == CTRL_CONN_ALL) {
        size_t i;
        for (i=1; i<ctrl_loop->conns_num; i++) {
            ctrl_conn_send_msg(ctrl_loop->conns[i], msg->xid, msg->msg);
        }
    } else {
        if (ctrl_loop->conns[msg->conn_id] != NULL) {
            ctrl_conn_send_msg(ctrl_loop->conns[msg->conn_id], msg->xid, msg->msg);
        } else {
            logger_log(ctrl_loop->logger, LOG_WARN, "Request for message on non-existing connection.");
        }
    }
    ofl_msg_free(msg->msg, OFL_NO_EXP, NULL/*errbuf*/);
    free(msg);

    return true;
}
