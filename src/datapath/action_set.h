/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef ACTION_SET_H
#define ACTION_SET_H 1

#include <sys/types.h>
#include <stdio.h>
#include "oflib/ofl.h"
#include "oflib/ofl_actions.h"
#include "oflib/ofl_structs.h"

struct act_set;
struct dp_loop;
struct pl_pkt;

struct act_set *
action_set_new();

void
action_set_free(struct act_set *set);

struct act_set *
action_set_clone(struct act_set *set);

void
action_set_write_acts(struct act_set *set, struct ofl_action_header **actions, size_t actions_num);

void
action_set_clear(struct act_set *set);

void
action_set_exec(struct dp_loop *dp_loop, struct act_set *set, struct pl_pkt *pl_pkt);

char *
action_set_to_string(struct act_set *set);

void
action_set_print(FILE *stream, struct act_set *set);

#endif /* ACTION_SET_H */
