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
 * A generic connection to a controller.
 */

#include <assert.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <openflow/openflow.h>
#include "datapath/dp.h"
#include "lib/openflow.h"
#include "lib/compiler.h"
#include "lib/logger_names.h"
#include "lib/util.h"
#include "logger/logger.h"
#include "logger/logger_mgr.h"
#include "oflib/ofl.h"
#include "oflib/ofl_messages.h"
#include "ctrl_conn.h"
#include "ctrl_conn_tcp.h"
#include "ctrl_int.h"
#include "ctrl.h"

#define TCP_TRANS       "tcp"

#define DEFAULT_TRANS   TCP_TRANS

/* Sends the buffer on the given connection. */
static void
send_buf(struct conn *conn, uint8_t *buf, size_t buf_size) {
    switch (conn->trans) {
        case CONN_TCP: {
            ctrl_conn_tcp_send(conn->private, buf, buf_size);
            break;
        }
        default: {
            logger_log(conn->logger, LOG_ERR, "ctrl_conn send called with unknown transport.");
            break;
        }
    }
}

/* Sends the buffer on the given connection. */
//NOTE: does not keep ownership of the message
void
ctrl_conn_send_msg(struct conn *conn, of_xid_t xid, struct ofl_msg_header *msg) {
    if (logger_is_enabled(conn->logger, LOG_DEBUG)) {
        char *str = ofl_msg_to_string(msg, OFL_NO_EXP, NULL/*errbuf*/);
        logger_log(conn->logger, LOG_DEBUG, "sending msg: (xid=%u) %s", xid, str);
        free(str);
    }

    uint8_t *buf;
    size_t buf_len;
    ofl_msg_pack(msg, xid, &buf, &buf_len, OFL_NO_EXP, NULL/*errbuf*/);
    send_buf(conn, buf, buf_len);
    free(buf);
}

/* Sends a hello message based on the incoming hello message. */
static void
send_hello(struct conn *conn, struct ofp_header *oh) {
    // just send back the same packet
    send_buf(conn, (uint8_t *)oh, sizeof(struct ofp_header));
}

/* Sends an echo request message. */
static void
send_echo_request(struct conn *conn) {
    struct ofp_header echo = {
        .version = OFP_VERSION,
        .type = OFPT_ECHO_REQUEST,
        .length = sizeof(struct ofp_header),
        .xid = 0
    };

    send_buf(conn, (uint8_t *)&echo, sizeof(struct ofp_header));
}

/* Replies to an echo request message. */
static void
send_echo_reply(struct conn *conn, struct ofp_header *oh) {
    // change the type to reply, and send back the same packet
    oh->type = OFPT_ECHO_REPLY;

    send_buf(conn, (uint8_t *)oh, ntohs(oh->length));
}

/* Sends an error message in reply to an incoming message. */
static void
send_error(struct conn *conn, of_xid_t xid, ofl_err err, uint8_t *msg, size_t msg_len) {
    struct ofl_msg_error error_msg =
              {{.type = OFPT_ERROR},
               .type = ofl_error_type(err),
               .code = ofl_error_code(err),
               .data_length = MAX(msg_len, 64),
               .data        = msg};

    ctrl_conn_send_msg(conn, xid, (struct ofl_msg_header *)&error_msg);
}


/* Tries to read and process an incoming OpenFlow message from the buffer.
 * If successful, returns the size of the message processed. Otherwise
 * returns zero. */
size_t
ctrl_conn_read(struct conn *conn, uint8_t *buf, size_t buf_size) {
    size_t msg_len = ctrl_conn_msg_len(buf, buf_size);

    if (msg_len == 0 || msg_len > buf_size) {
        return 0;
    }

    struct ofp_header *oh = (struct ofp_header *)buf;

    switch (oh->type) {
        //Hello and echo is handled in control
        case OFPT_HELLO: {
            // TODO check hello version
            send_hello(conn, oh);
            logger_log(conn->logger, LOG_DEBUG, "Answered hello.");
            break;
        }
        case OFPT_ECHO_REQUEST: {
            send_echo_reply(conn, oh);
            logger_log(conn->logger, LOG_DEBUG, "Answered echo request.");
            break;
        }
        case OFPT_ECHO_REPLY: {
            // swallow echo replies
            logger_log(conn->logger, LOG_DEBUG, "Received echo reply.");
            break;
        }
        //The rest of messages is handled by dp
        default: {
            struct ofl_msg_header *msg;
            of_xid_t xid;
            ofl_err err = ofl_msg_unpack(buf, msg_len, &msg, &xid, OFL_NO_EXP, NULL/*errbuf*/);
            if (err != 0) {
                // error unpacking the message
                send_error(conn, 0, err, buf, msg_len);
            } else {
                dp_recv_msg(conn->ctrl_loop->dp, conn->id, xid, msg, buf, msg_len);
            }
            break;
        }
    }
    return msg_len;
}

/* If buffer stores a partial OpenFlow message, returns the total length
 * of the message. If buffer is invalid (i.e. does not contain enough
 * bytes, returns zero. */
inline size_t
ctrl_conn_msg_len(uint8_t *buf, size_t buf_size) {
    if (buf_size < sizeof(struct ofp_header)) {
        return 0;
    }

    struct ofp_header *oh = (struct ofp_header *)buf;
    return ntohs(oh->length);
}


void
ctrl_conn_idle(struct conn *conn) {
    send_echo_request(conn);
}

/* Request for adding a new controller connection. */
void
ctrl_conn_add(struct ctrl_loop *ctrl_loop, const char *trans, const char *host, const char *port) {
    assert(host != NULL);

    if (ctrl_loop->conns_num == MAX_CONNS) {
        logger_log(ctrl_loop->logger, LOG_ERR, "Cannot add more connections.");
        return;
    }

    if (trans == NULL || strcmp(trans, TCP_TRANS) == 0) {
        struct conn *conn = malloc(sizeof(struct conn));
        conn->ctrl_loop = ctrl_loop;
        conn->logger = logger_mgr_get(LOGGER_NAME_CTRL_CONN, dp_get_uid(ctrl_loop->dp), ctrl_loop->conns_num);
        conn->id = ctrl_loop->conns_num;
        conn->trans = CONN_TCP;

        void *tcp = ctrl_conn_tcp_new(conn, host, port);
        if (tcp != NULL) {
            conn->private = tcp;
            ctrl_loop->conns[ctrl_loop->conns_num] = conn;
            ctrl_loop->conns_num ++;

            logger_log(conn->logger, LOG_DEBUG, "Created connection: %s:%s:%s.",
                    STR_DEF(trans, DEFAULT_TRANS), host, STR_DEF(port, ""));
        } else {
            free(conn);
            logger_log(ctrl_loop->logger, LOG_WARN, "Error adding: %s:%s:%s.",
                    STR_DEF(trans, DEFAULT_TRANS), host, STR_DEF(port, ""));
        }
    } else {
        logger_log(ctrl_loop->logger, LOG_WARN, "Trying to add controller with unknown transport: %s:%s:%s.",
                STR_DEF(trans, DEFAULT_TRANS), host, STR_DEF(port, ""));
    }
}
