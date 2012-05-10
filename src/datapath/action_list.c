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
 * Implements OpenFlow action-list related functions.
 */
#include <stdbool.h>
#include "lib/openflow.h"
#include "logger/logger.h"
#include "oflib/ofl.h"
#include "oflib/ofl_actions.h"
#include "action.h"
#include "action_list.h"
#include "dp.h"
#include "dp_int.h"
#include "group_table.h"
#include "pipeline_packet.h"

/* Executes actions in the action-list on the given packet. */
void
action_list_exec(struct dp_loop *dp_loop, struct pl_pkt *pl_pkt,
        struct ofl_action_header **actions, size_t actions_num) {
    logger_log(pl_pkt->logger, LOG_DEBUG, "Executing action list.");
    size_t i;
    for (i=0; i < actions_num; i++) {
        struct act_res res = action_exec(pl_pkt, actions[i]);

        switch (res.type) {
            case DP_ACT_GROUP: {
                logger_log(pl_pkt->logger, LOG_DEBUG, "Group action; executing group (%u).", res.group_id);
                group_table_exec(dp_loop->groups, pl_pkt, res.group_id);
                break;
            }
            case DP_ACT_PORT: {
                logger_log(pl_pkt->logger, LOG_DEBUG, "Port action; sending to port (%u).", res.port.port_id);
                dp_pl_pkt_to_port(dp_loop, res.port.port_id, res.port.max_len, pl_pkt);
                break;
            }
            default: {
                break;
            }
        }
    }
    logger_log(pl_pkt->logger, LOG_DEBUG, "Finished executing action list.");
}

/* Validates the actions in the action list. */
ofl_err
action_list_validate(struct dp_loop *dp_loop, struct ofl_action_header **actions, size_t actions_num) {
    size_t i;
    for (i=0; i < actions_num; i++) {
        ofl_err ret = action_validate(dp_loop, actions[i]);
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

/* Tells whether the any of the actions in the action list output to the given port. */
bool
action_list_has_out_port(struct ofl_action_header **actions, size_t actions_num, of_port_no_t port) {
    size_t i;
    for (i=0; i < actions_num; i++) {
        if (actions[i]->type == OFPAT_OUTPUT) {
            struct ofl_action_output *ao = (struct ofl_action_output *)actions[i];
            if (ao->port == port) {
                return true;
            }
        }
    }
    return false;
}

/* Tells whether the any of the actions in the action list output to the given group. */
bool
action_list_has_out_group(struct ofl_action_header **actions, size_t actions_num, of_groupid_t group) {
    size_t i;
    for (i=0; i < actions_num; i++) {
        if (actions[i]->type == OFPAT_GROUP) {
            struct ofl_action_group *ag = (struct ofl_action_group *)actions[i];
            if (ag->group_id == group) {
                return true;
            }
        }
    }
    return false;
}
