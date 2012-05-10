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
 * Represents the processing pipeline logic.
 * Run in the thread of the DP.
 */

#include <stdint.h>
#include <ev.h>
#include <pthread.h>
#include <openflow/openflow.h>
#include "control/ctrl.h"
#include "oflib/ofl_messages.h"
#include "oflib/ofl_structs.h"
#include "oflib/ofl.h"
#include "oflib/ofl.h"
#include "lib/util.h"
#include "logger/logger.h"
#include "lib/pkt_buf.h"
#include "lib/openflow.h"
#include "port/port_drv.h"
#include "action.h"
#include "action_set.h"
#include "dp.h"
#include "dp_bufs.h"
#include "dp_int.h"
#include "pipeline.h"
#include "pipeline_packet.h"
#include "flow_table.h"
#include "group_table.h"


/* Called by the DP to process an incoming packet. */
void
pipeline_process(struct dp_loop *dp_loop, struct pl_pkt *pl_pkt) {
    if (logger_is_enabled(dp_loop->logger_pl, LOG_DEBUG)) {
        char *str = pl_pkt_to_string(pl_pkt);

        logger_log(dp_loop->logger_pl, LOG_DEBUG, "Received packet:\n%s", str);
        free(str);
    }

    pl_pkt->logger = dp_loop->logger_pkt;

    of_tableid_t next_table = 0;

    while (next_table != OF_ALL_TABLE) {
        logger_log(dp_loop->logger_pl, LOG_DEBUG, "Trying table %u.", next_table);

        if (!pl_pkt_is_ttl_valid(pl_pkt)) {
            if ((dp_loop->of_conf.flags & OFPC_INVALID_TTL_TO_CONTROLLER) != 0) {
                logger_log(dp_loop->logger_pl, LOG_INFO, "Packet has invalid TTL, sending to controller.");

                // NOTE: no valid reason for invalid ttl in spec.
                dp_pl_pkt_to_ctrl(dp_loop, dp_loop->of_conf.miss_send_len, pl_pkt, OFPR_NO_MATCH);
            } else {
                logger_log(dp_loop->logger_pl, LOG_INFO, "Packet has invalid TTL, dropping.");
                //TODO check clean up packet
                pl_pkt_free(pl_pkt, true);
            }
            return;
        }

        pl_pkt->table_id = next_table;
        next_table = flow_table_exec(dp_loop->tables[next_table], pl_pkt, ev_now(dp_loop->loop));
    }

    logger_log(dp_loop->logger_pl, LOG_DEBUG, "Finished pipeline, executing action set.");
    action_set_exec(dp_loop, pl_pkt->act_set, pl_pkt);
    pl_pkt_free(pl_pkt, true);
    logger_log(dp_loop->logger_pl, LOG_DEBUG, "Pipeline done.");
}
