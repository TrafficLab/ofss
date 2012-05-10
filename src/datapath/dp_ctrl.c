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
 * Implements the DP's controller message handling functionality.
 * These functions are always executed in the DP's thread.
 */

#include <ev.h>
#include <pthread.h>
#include "control/ctrl.h"
#include "oflib/ofl_messages.h"
#include "oflib/ofl_structs.h"
#include "oflib/ofl.h"
#include "oflib/ofl.h"
#include "lib/util.h"
#include "logger/logger.h"
#include "lib/pkt_buf.h"
#include "port/port_drv.h"
#include "action.h"
#include "action_list.h"
#include "action_set.h"
#include "pipeline.h"
#include "capabilities.h"
#include "dp_bufs.h"
#include "dp_int.h"
#include "pipeline_packet.h"
#include "flow_table.h"
#include "group_table.h"

/* Send an error message to the controller(s). */
static void
send_error(struct dp_loop *dp_loop, struct dp_msg *msg, ofl_err err) {
    //NOTE: keeps the ofl_msg as part of the error
    struct ofl_msg_error *error = malloc(sizeof(struct ofl_msg_error));
    error->header.type = OFPT_ERROR;
    error->type = ofl_error_type(err);
    error->code = ofl_error_code(err);
    error->data        = msg->ofp_msg;
    error->data_length = msg->ofp_msg_len;

    ctrl_send_msg(dp_loop->ctrl, msg->conn_id, msg->xid, (struct ofl_msg_header *)error);
}

/* Handle description request. */
static ofl_err
stats_desc(struct dp_loop *dp_loop, struct dp_msg *msg) {
    struct ofl_msg_stats_reply_desc *rep = malloc(sizeof(struct ofl_msg_stats_reply_desc));
    rep->header.header.type = OFPT_STATS_REPLY;
    rep->header.type = OFPST_DESC;
    rep->header.flags = 0x0000;

    rep->mfr_desc = memcpy(malloc(DESC_STR_LEN), dp_loop->desc->mfr_desc, DESC_STR_LEN);
    rep->hw_desc = memcpy(malloc(DESC_STR_LEN), dp_loop->desc->hw_desc, DESC_STR_LEN);
    rep->sw_desc = memcpy(malloc(DESC_STR_LEN), dp_loop->desc->sw_desc, DESC_STR_LEN);
    rep->dp_desc = memcpy(malloc(DESC_STR_LEN), dp_loop->desc->dp_desc, DESC_STR_LEN);
    rep->serial_num = memcpy(malloc(SERIAL_NUM_LEN), dp_loop->desc->serial_num, SERIAL_NUM_LEN);

    ctrl_send_msg(dp_loop->ctrl, msg->conn_id, msg->xid, (struct ofl_msg_header *)rep);

    ofl_msg_free(msg->msg, OFL_NO_EXP, NULL/*errbuf*/);
    free(msg->ofp_msg);
    return 0;
}

/* Handle features request. */
static ofl_err
feat_req(struct dp_loop *dp_loop, struct dp_msg *msg) {
    struct ofl_msg_features_reply *rep = malloc(sizeof(struct ofl_msg_features_reply));

    rep->header.type = OFPT_FEATURES_REPLY;
    rep->datapath_id = dp_loop->dpid;
    rep->n_buffers    = dp_bufs_size(dp_loop->bufs);
    rep->n_tables     = TABLES_NUM;
    rep->capabilities = DP_CAPABILITIES;

    struct dp *dp = dp_loop->dp;
    pthread_rwlock_rdlock(dp->ports_lock);
    rep->ports_num = dp->ports_num;
    rep->ports     = malloc(sizeof(struct ofl_port *) * rep->ports_num);

    size_t i, j;
    j = 0;
    for (i = 1; i < MAX_PORTS; i++) {
        struct dp_port *dp_port = dp->ports[i];
        if (dp_port != NULL) {
            pthread_rwlock_rdlock(dp_port->rwlock);
            struct port_drv *drv = dp_port->drv;
            size_t drv_port_no = dp_port->drv_port_no;
            pthread_rwlock_unlock(dp_port->rwlock);
            rep->ports[j] = port_drv_get_port_desc(drv, drv_port_no);
            j++;
            if (j == rep->ports_num) {
                break;
            }
        }
    }
    pthread_rwlock_unlock(dp->ports_lock);

    ctrl_send_msg(dp_loop->ctrl, msg->conn_id, msg->xid, (struct ofl_msg_header *)rep);
    ofl_msg_free(msg->msg, OFL_NO_EXP, NULL/*errbuf*/);
    free(msg->ofp_msg);
    return 0;
}

/* Handle queue get config request. */
static ofl_err
queue_req(struct dp_loop *dp_loop, struct dp_msg *msg) {
    //NOTE: no queues are supported currently
    struct ofl_msg_queue_get_config_request *req = (struct ofl_msg_queue_get_config_request *)(msg->msg);

    struct dp *dp = dp_loop->dp;
    pthread_rwlock_rdlock(dp->ports_lock);
    bool valid = (dp->ports[req->port] != NULL);
    pthread_rwlock_unlock(dp->ports_lock);

    if (!valid) {
        return ofl_error(OFPET_QUEUE_OP_FAILED, OFPQOFC_BAD_PORT);
    }

    struct ofl_msg_queue_get_config_reply *rep = malloc(sizeof(struct ofl_msg_queue_get_config_reply));
    rep->header.type = OFPT_QUEUE_GET_CONFIG_REPLY;
    rep->port       = req->port;
    rep->queues_num = 0;
    rep->queues = NULL;

    ctrl_send_msg(dp_loop->ctrl, msg->conn_id, msg->xid, (struct ofl_msg_header *)rep);
    ofl_msg_free(msg->msg, OFL_NO_EXP, NULL/*errbuf*/);
    free(msg->ofp_msg);
    return 0;
}

/* Handle port stats request. */
static ofl_err
stats_port(struct dp_loop *dp_loop, struct dp_msg *msg) {
    struct ofl_msg_stats_request_port *req = (struct ofl_msg_stats_request_port *)(msg->msg);

    if (req->port_no == OFPP_ANY) {
        struct ofl_msg_stats_reply_port *rep = malloc(sizeof(struct ofl_msg_stats_reply_port));
        rep->header.header.type = OFPT_STATS_REPLY;
        rep->header.type = OFPST_PORT;
        rep->header.flags = 0x0000;

        struct dp *dp = dp_loop->dp;
        pthread_rwlock_rdlock(dp->ports_lock);
        rep->stats_num = dp->ports_num;
        rep->stats     = malloc(sizeof(struct ofl_port_stats *) * rep->stats_num);

        size_t i, j;
        j = 0;
        for (i = 1; i < MAX_PORTS; i++) {
            struct dp_port *dp_port = dp->ports[i];
            if (dp_port != NULL) {
                pthread_rwlock_rdlock(dp_port->rwlock);
                struct port_drv *drv = dp_port->drv;
                size_t drv_port_no = dp_port->drv_port_no;
                pthread_rwlock_unlock(dp_port->rwlock);
                rep->stats[j] = port_drv_get_port_stats(drv, drv_port_no);
                j++;
                if (j == rep->stats_num) {
                    break;
                }
            }
        }
        pthread_rwlock_unlock(dp->ports_lock);

        ctrl_send_msg(dp_loop->ctrl, msg->conn_id, msg->xid, (struct ofl_msg_header *)rep);
        ofl_msg_free(msg->msg, OFL_NO_EXP, NULL/*errbuf*/);
        free(msg->ofp_msg);
    } else {

        struct dp *dp = dp_loop->dp;
        pthread_rwlock_rdlock(dp->ports_lock);
        struct dp_port *dp_port = dp->ports[req->port_no];
        pthread_rwlock_unlock(dp->ports_lock);

        if  (dp_port == NULL) {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_STAT); //TODO is this error code ok?
        }

        struct ofl_msg_stats_reply_port *rep = malloc(sizeof(struct ofl_msg_stats_reply_port));
        rep->header.header.type = OFPT_STATS_REPLY;
        rep->header.type = OFPST_PORT;
        rep->header.flags = 0x0000;
        rep->stats_num = 1;
        rep->stats = malloc(sizeof(struct ofl_port_stats *));

        pthread_rwlock_rdlock(dp_port->rwlock);
        struct port_drv *drv = dp_port->drv;
        size_t drv_port_no = dp_port->drv_port_no;
        pthread_rwlock_unlock(dp_port->rwlock);

        rep->stats[0] = port_drv_get_port_stats(drv, drv_port_no);

        ctrl_send_msg(dp_loop->ctrl, msg->conn_id, msg->xid, (struct ofl_msg_header *)rep);

        ofl_msg_free(msg->msg, OFL_NO_EXP, NULL/*errbuf*/);
        free(msg->ofp_msg);
    }
    return 0;
}

/* Handle queue stats request. */
static ofl_err
stats_queue(struct dp_loop *dp_loop, struct dp_msg *msg) {
    //NOTE: queues are not supported for now
    struct ofl_msg_stats_request_queue *req = (struct ofl_msg_stats_request_queue *)(msg->msg);

    if (req->port_no != OFPP_ANY) {
        if (req->queue_id != OFPQ_ALL) {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_STAT); //TODO is this error code ok?
        } else {
            struct dp *dp = dp_loop->dp;
             pthread_rwlock_rdlock(dp->ports_lock);
             struct dp_port *dp_port = dp->ports[req->port_no];
             pthread_rwlock_unlock(dp->ports_lock);

             if  (dp_port == NULL) {
                 return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_STAT); //TODO is this error code ok?
             }
        }
    }

    struct ofl_msg_stats_reply_queue *rep = malloc(sizeof(struct ofl_msg_stats_reply_queue));
    rep->header.header.type = OFPT_STATS_REPLY;
    rep->header.type = OFPST_QUEUE;
    rep->header.flags = 0x0000;
    rep->stats_num   = 0;
    rep->stats       = NULL;

    ctrl_send_msg(dp_loop->ctrl, msg->conn_id, msg->xid, (struct ofl_msg_header *)rep);

    ofl_msg_free(msg->msg, OFL_NO_EXP, NULL/*errbuf*/);
    free(msg->ofp_msg);
    return 0;
}

/* Handle port mod request. */
static ofl_err
port_mod(struct dp_loop *dp_loop, struct dp_msg *msg) {
    struct ofl_msg_port_mod *req = (struct ofl_msg_port_mod *)(msg->msg);

    struct dp *dp = dp_loop->dp;
    pthread_rwlock_rdlock(dp->ports_lock);
    struct dp_port *dp_port = dp->ports[req->port_no];
    pthread_rwlock_unlock(dp->ports_lock);

    if  (dp_port == NULL) {
        return ofl_error(OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_PORT);
    }

    pthread_rwlock_wrlock(dp_port->rwlock);
    struct port_drv *drv = dp_port->drv;
    size_t drv_port_no = dp_port->drv_port_no;

    // Make sure the port id hasn't changed since this was sent
    const uint8_t *hw_addr = port_drv_get_port_addr(drv, drv_port_no);
    if (memcmp(req->hw_addr, hw_addr, OFP_ETH_ALEN) != 0) {
        pthread_rwlock_unlock(dp_port->rwlock);
        return ofl_error(OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_HW_ADDR);
    }

    if (req->mask) {
        dp_port->of_config &= ~req->mask;
        dp_port->of_config |= req->config & req->mask;
    }

    port_drv_port_mod(drv, drv_port_no, dp_port->of_config);

    pthread_rwlock_unlock(dp_port->rwlock);

    ofl_msg_free(msg->msg, OFL_NO_EXP, NULL/*errbuf*/);
    free(msg->ofp_msg);
    return 0;
}

/* Handle flow_stats request. */
static ofl_err
stats_flow(struct dp_loop *dp_loop, struct dp_msg *msg) {
    struct ofl_msg_stats_request_flow *req = (struct ofl_msg_stats_request_flow *)(msg->msg);

    struct ofl_flow_stats **stats = malloc(sizeof(struct ofl_flow_stats *));
    size_t stats_size = 1;
    size_t stats_num = 0;

    if (req->table_id == 0xff) {
        size_t i;
        for (i=0; i<TABLES_NUM; i++) {
            flow_table_stats_flow(dp_loop->tables[i], req, &stats, &stats_size, &stats_num);
        }
    } else {
        //TODO check table num < TABLES_NUM (if defined to lower than 255)
        flow_table_stats_flow(dp_loop->tables[req->table_id], req, &stats, &stats_size, &stats_num);
    }

    struct ofl_msg_stats_reply_flow *rep = malloc(sizeof(struct ofl_msg_stats_reply_flow));
    rep->header.header.type = OFPT_STATS_REPLY;
    rep->header.type = OFPST_FLOW;
    rep->header.flags = 0x0000;
    rep->stats = stats;
    rep->stats_num = stats_num;

    ctrl_send_msg(dp_loop->ctrl, msg->conn_id, msg->xid, (struct ofl_msg_header *)rep);

    ofl_msg_free(msg->msg, OFL_NO_EXP, NULL/*errbuf*/);
    free(msg->ofp_msg);
    return 0;
}

/* Handle flow aggregate stats request. */
static ofl_err
stats_aggr(struct dp_loop *dp_loop, struct dp_msg *msg) {
    struct ofl_msg_stats_request_flow *req = (struct ofl_msg_stats_request_flow *)(msg->msg);

    struct ofl_msg_stats_reply_aggregate *rep = malloc(sizeof(struct ofl_msg_stats_reply_aggregate));
    rep->header.header.type = OFPT_STATS_REPLY;
    rep->header.type = OFPST_AGGREGATE;
    rep->header.flags = 0x0000;
    rep->packet_count = 0;
    rep->byte_count   = 0;
    rep->flow_count   = 0;

    if (req->table_id == 0xff) {
        size_t i;
        for (i=0; i<TABLES_NUM; i++) {
            struct flow_table_aggr aggr = flow_table_stats_aggr(dp_loop->tables[i], req);
            rep->packet_count += aggr.packet_count;
            rep->byte_count += aggr.byte_count;
            rep->flow_count += aggr.flow_count;
        }

    } else {
        //TODO: check table id?
        struct flow_table_aggr aggr = flow_table_stats_aggr(dp_loop->tables[req->table_id], req);
        rep->packet_count += aggr.packet_count;
        rep->byte_count += aggr.byte_count;
        rep->flow_count += aggr.flow_count;
    }

    ctrl_send_msg(dp_loop->ctrl, msg->conn_id, msg->xid, (struct ofl_msg_header *)rep);

    ofl_msg_free(msg->msg, OFL_NO_EXP, NULL/*errbuf*/);
    free(msg->ofp_msg);
    return 0;
}

/* Handle table stats request. */
static ofl_err
stats_table(struct dp_loop *dp_loop, struct dp_msg *msg) {
    struct ofl_table_stats **stats = malloc(sizeof(struct ofl_table_stats *) * TABLES_NUM);

    size_t i;
    for (i=0; i<TABLES_NUM; i++) {
        stats[i] = flow_table_stats(dp_loop->tables[i]);
    }

    struct ofl_msg_stats_reply_table *rep = malloc(sizeof(struct ofl_msg_stats_reply_table));
    rep->header.header.type = OFPT_STATS_REPLY;
    rep->header.type = OFPST_TABLE;
    rep->header.flags = 0x0000;
    rep->stats        = stats;
    rep->stats_num = TABLES_NUM;

    ctrl_send_msg(dp_loop->ctrl, msg->conn_id, msg->xid, (struct ofl_msg_header *)rep);

    ofl_msg_free(msg->msg, OFL_NO_EXP, NULL/*errbuf*/);
    free(msg->ofp_msg);
    return 0;
}

/* Handle get config request. */
static ofl_err
get_conf(struct dp_loop *dp_loop, struct dp_msg *msg) {
    struct ofl_msg_get_config_reply *rep = malloc(sizeof(struct ofl_msg_get_config_reply));
    rep->header.type = OFPT_GET_CONFIG_REPLY;
    rep->config = memcpy(malloc(sizeof(struct ofl_config)), &(dp_loop->of_conf), sizeof(struct ofl_config));

    ctrl_send_msg(dp_loop->ctrl, msg->conn_id, msg->xid, (struct ofl_msg_header *)rep);
    ofl_msg_free(msg->msg, OFL_NO_EXP, NULL/*errbuf*/);
    free(msg->ofp_msg);
    return 0;
}

/* Handle set config request. */
static ofl_err
set_conf(struct dp_loop *dp_loop, struct dp_msg *msg) {
    struct ofl_msg_set_config *req = (struct ofl_msg_set_config *)(msg->msg);

    uint16_t flags = req->config->flags & OFPC_FRAG_MASK;
    if ((flags & OFPC_FRAG_MASK) != OFPC_FRAG_NORMAL
        && (flags & OFPC_FRAG_MASK) != OFPC_FRAG_DROP) {
        flags = (flags & ~OFPC_FRAG_MASK) | OFPC_FRAG_DROP;
    }

    dp_loop->of_conf.flags = flags;
    dp_loop->of_conf.miss_send_len = req->config->miss_send_len;

    ofl_msg_free(msg->msg, OFL_NO_EXP, NULL/*errbuf*/);
    free(msg->ofp_msg);
    return 0;
}

/* Handle packet out message. */
static ofl_err
pkt_out(struct dp_loop *dp_loop, struct dp_msg *msg) {
    struct ofl_msg_packet_out *req = (struct ofl_msg_packet_out *)(msg->msg);

    ofl_err err = action_list_validate(dp_loop, req->actions, req->actions_num);
    if (err != 0) {
        return err;
    }

    struct pl_pkt *pl_pkt;
    if (req->buffer_id == OF_NO_BUFFER) {
        struct pkt_buf *pkt = pkt_buf_new_use(req->data, req->data_length);
        pl_pkt = pl_pkt_new(pkt, true, req->in_port);
        pl_pkt->logger = dp_loop->logger_pkt;
    } else {
        struct pkt_buf *pkt = dp_bufs_get(dp_loop->bufs, req->buffer_id);
        if (pkt == NULL) {
            // This might be a wrong req., or a timed out buffer
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BUFFER_EMPTY);
        }
        pl_pkt = pl_pkt_new(pkt, true, req->in_port);
        pl_pkt->logger = dp_loop->logger_pkt;
    }

    action_list_exec(dp_loop, pl_pkt, req->actions, req->actions_num);
    pl_pkt_free(pl_pkt, true);

    ofl_msg_free_packet_out(req, false, OFL_NO_EXP, NULL/*errbuf*/); // if buffer was used, pkt is null anyway...
    free(msg->ofp_msg);
    return 0;
}

/* Handle flow mods.
 * Note: the result of using table_id = 0xff is undefined in the spec.
 *       for now it is accepted for delete commands, meaning to delete
 *       from all tables */
static ofl_err
flow_mod(struct dp_loop *dp_loop, struct dp_msg *msg) {
    struct ofl_msg_flow_mod *req = (struct ofl_msg_flow_mod *)(msg->msg);

    //validate actions in instructions
    ofl_err error;
    size_t i;
    for (i=0; i< req->instructions_num; i++) {
        if (req->instructions[i]->type == OFPIT_APPLY_ACTIONS ||
            req->instructions[i]->type == OFPIT_WRITE_ACTIONS) {
            struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)(req->instructions[i]);

            error = action_list_validate(dp_loop, ia->actions, ia->actions_num);
            if (error) {
                logger_log(dp_loop->logger_ctrl, LOG_INFO, "Invalid actions in flow mod %d.", error);
                return error;
            }
        }
    }

    bool match_kept = false;
    bool insts_kept = false;

    if (req->table_id == 0xff) {
        if (req->command == OFPFC_DELETE || req->command == OFPFC_DELETE_STRICT) {

            error = 0;
            for (i=0; i < TABLES_NUM; i++) {
                error = flow_table_flow_mod(dp_loop->tables[i], req, &match_kept, &insts_kept);
                if (error != 0) {
                    //TODO: is this OK ? executing only half-way...
                    return error;
                }
            }
            ofl_msg_free_flow_mod(req, !match_kept, !insts_kept, OFL_NO_EXP, NULL/*errbuf*/);
            free(msg->ofp_msg);
        } else {
            send_error(dp_loop, msg, ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_TABLE_ID));
            ofl_msg_free_flow_mod(req, true, true, OFL_NO_EXP, NULL/*errbuf*/);
        }
    } else {
        error = flow_table_flow_mod(dp_loop->tables[req->table_id], req, &match_kept, &insts_kept);
        if (error != 0) {
            return error;
        }
        if ((req->command == OFPFC_ADD || req->command == OFPFC_MODIFY || req->command == OFPFC_MODIFY_STRICT) &&
                            req->buffer_id != OF_NO_BUFFER) {
            // run buffered message through pipeline
            struct pkt_buf *pkt = dp_bufs_get(dp_loop->bufs, req->buffer_id);
            if (pkt != NULL) {
                struct pl_pkt *pl_pkt = pl_pkt_new(pkt, true, OFPP_CONTROLLER);
                pl_pkt->logger = dp_loop->logger_pkt;
                pipeline_process(dp_loop, pl_pkt);
                pl_pkt_free(pl_pkt, true);
            } else {
                logger_log(dp_loop->logger_ctrl, LOG_INFO, "The buffer flow_mod referred to was empty (%u).", req->buffer_id);
            }
        }

        ofl_msg_free_flow_mod(req, !match_kept, !insts_kept, OFL_NO_EXP, NULL/*errbuf*/);
        free(msg->ofp_msg);
    }

    return 0;
}

/* Handle table mod request. */
static ofl_err
table_mod(struct dp_loop *dp_loop, struct dp_msg *msg) {
    struct ofl_msg_table_mod *req = (struct ofl_msg_table_mod *)(msg->msg);

    if (req->table_id == 0xff) {
        size_t i;
        for (i=0; i<TABLES_NUM; i++) {
            flow_table_mod(dp_loop->tables[i], req->config);
        }
    } else {
        //TODO check table_id
        flow_table_mod(dp_loop->tables[req->table_id], req->config);
    }

    ofl_msg_free(msg->msg, OFL_NO_EXP, NULL/*errbuf*/);
    free(msg->ofp_msg);
    return 0;
}

/* Handle barrier request.
 * NOTE: even though the implementation is multi-threaded
   processing is still done in sequence in the DP thread. */
static ofl_err
barrier(struct dp_loop *dp_loop, struct dp_msg *msg) {

    // can reuse incoming message
    msg->msg->type = OFPT_BARRIER_REPLY;

    ctrl_send_msg(dp_loop->ctrl, msg->conn_id, msg->xid, msg->msg);
    free(msg->ofp_msg);
    return 0;
}

/* Dispatch stats requests. */
static ofl_err
stats(struct dp_loop *dp_loop, struct dp_msg *msg) {
    struct ofl_msg_stats_request_header *stat = (struct ofl_msg_stats_request_header *)(msg->msg);

    switch (stat->type) {
        case OFPST_DESC: {
            return stats_desc(dp_loop, msg);
        }
        case OFPST_FLOW: {
            return stats_flow(dp_loop, msg);
        }
        case OFPST_AGGREGATE: {
            return stats_aggr(dp_loop, msg);
        }
        case OFPST_TABLE: {
            return stats_table(dp_loop, msg);
        }
        case OFPST_GROUP: {
            return group_table_stats_group(dp_loop->groups, msg);
        }
        case OFPST_GROUP_DESC: {
            return group_table_stats_group_desc(dp_loop->groups, msg);
        }
        case OFPST_PORT: {
            return stats_port(dp_loop, msg);
        }
        case OFPST_QUEUE: {
            return stats_queue(dp_loop, msg);
        }
        default: {
            logger_log(dp_loop->logger_ctrl, LOG_INFO, "Received unexpected stats type: %d.", stat->type);
            break;
        }
    }
    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_STAT);
}




/* Dispatches incoming controller messages to handler functions. */
void
dp_ctrl_recv_msg(struct dp_loop *dp_loop, struct dp_msg *msg) {

    if (logger_is_enabled(dp_loop->logger_ctrl, LOG_DEBUG)) {
        char *str = ofl_msg_to_string(msg->msg, OFL_NO_EXP, NULL/*errbuf*/);
        logger_log(dp_loop->logger_ctrl, LOG_DEBUG, "received msg: (xid=%u) %s", msg->xid, str);
        free(str);
    }

    ofl_err error = 0;

    switch (msg->msg->type) {
        case OFPT_FEATURES_REQUEST: {
            error = feat_req(dp_loop, msg);
            break;
        }
        case OFPT_GET_CONFIG_REQUEST: {
            error = get_conf(dp_loop, msg);
            break;
        }
        case OFPT_SET_CONFIG: {
            error = set_conf(dp_loop, msg);
            break;
        }
        case OFPT_PACKET_OUT: {
            error = pkt_out(dp_loop, msg);
            break;
        }
        case OFPT_FLOW_MOD: {
            error = flow_mod(dp_loop, msg);
            break;
        }
        case OFPT_GROUP_MOD: {
            error = group_table_group_mod(dp_loop->groups, msg);
            break;
        }
        case OFPT_PORT_MOD: {
            error = port_mod(dp_loop, msg);
            break;
        }
        case OFPT_TABLE_MOD: {
            error = table_mod(dp_loop, msg);
            break;
        }
        case OFPT_BARRIER_REQUEST: {
            error = barrier(dp_loop, msg);
            break;
        }
        case OFPT_STATS_REQUEST: {
            error = stats(dp_loop, msg);
            break;
        }
        case OFPT_QUEUE_GET_CONFIG_REQUEST: {
            error = queue_req(dp_loop, msg);
            break;
        }
        default: {
            logger_log(dp_loop->logger_ctrl, LOG_INFO, "Received unexpected message type: %d.", msg->msg->type);
            error = ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
        }
    }

    if (error != 0) {
        send_error(dp_loop, msg, error);
        ofl_msg_free(msg->msg, OFL_NO_EXP, NULL/*errbuf*/);
        return;
    }

}

/* Sends a message to the controller(s). Used internally by the pipeline. */
void
dp_ctrl_send_msg(struct dp_loop *dp_loop, size_t conn_id, of_xid_t xid, struct ofl_msg_header *msg) {
    ctrl_send_msg(dp_loop->ctrl, conn_id, xid, msg);
}
