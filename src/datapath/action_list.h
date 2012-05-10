/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef ACTION_LIST_H
#define ACTION_LIST_H 1

#include <stdbool.h>
#include "lib/openflow.h"
#include "oflib/ofl.h"
#include "oflib/ofl_actions.h"

struct dp_loop;

void
action_list_exec(struct dp_loop *dp_loop, struct pl_pkt *pl_pkt,
                 struct ofl_action_header **actions, size_t actions_num);


ofl_err
action_list_validate(struct dp_loop *dp_loop, struct ofl_action_header **actions, size_t actions_num);


bool
action_list_has_out_port(struct ofl_action_header **actions, size_t actions_num, of_port_no_t port);

bool
action_list_has_out_group(struct ofl_action_header **actions, size_t actions_num, of_groupid_t group);


#endif /* ACTION_LIST_H */
