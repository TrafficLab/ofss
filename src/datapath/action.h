/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef ACTION_H
#define ACTION_H 1

#include <stdbool.h>
#include "lib/openflow.h"

struct dp_loop;
struct pl_pkt;
struct ofl_action_header;

enum act_res_type {
    DP_ACT_NONE,
    DP_ACT_PORT,
    DP_ACT_GROUP
};

/* Represents the result of an action if it does not
 * manipulate the packet (or metadata), but has to
 * be done to the packet.
 * Currently this is: output on a port, or send it to
 * a group.
 */
struct act_res {
    enum act_res_type type;
    union {
        struct {
            of_port_no_t port_id;
            uint16_t     max_len;
        } port;
        of_groupid_t group_id;
    } u;
};

ofl_err
action_validate(struct dp_loop *dp_loop, struct ofl_action_header *act);


struct act_res
action_exec(struct pl_pkt *pl_pkt, struct ofl_action_header *action);





#endif /* ACTION_H */
