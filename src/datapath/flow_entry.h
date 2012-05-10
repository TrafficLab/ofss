/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef FLOW_ENTRY_H
#define FLOW_ENTRY_H 1

#include <ev.h>
#include "oflib/ofl_messages.h"

struct flow_aggr {
    uint64_t   packet_count;
    uint64_t   byte_count;
};

struct flow_entry;
struct flow_table;
struct pl_pkt;

struct flow_entry *
flow_entry_new(struct flow_table *flow_table, uint32_t flow_ref, struct ofl_msg_flow_mod *mod, ev_tstamp now);

void
flow_entry_free(struct flow_entry *entry, bool free_stats);

void
flow_entry_remove(struct dp_loop *dp_loop, struct flow_entry *entry, uint8_t reason);


bool
flow_entry_matches_mod(struct flow_entry *entry, struct ofl_msg_flow_mod *mod, bool strict, bool check_cookie);

bool
flow_entry_matches_stat(struct flow_entry *entry, struct ofl_msg_stats_request_flow *stat);

bool
flow_entry_matches_pkt(struct flow_entry *flow, struct pl_pkt *pl_pkt);


bool
flow_entry_overlaps(struct flow_entry *entry, struct ofl_msg_flow_mod *mod);

void
flow_entry_replace_instructions(struct flow_entry *entry,
                                      size_t instructions_num,
                                      struct ofl_instruction_header **instructions);

struct ofl_flow_stats *
flow_entry_stats(struct flow_entry *entry, ev_tstamp now);

struct flow_aggr
flow_entry_stats_aggr(struct flow_entry *entry);

bool
flow_entry_idle_timeout(struct flow_entry *entry, ev_tstamp now);

bool
flow_entry_hard_timeout(struct flow_entry *entry, ev_tstamp now);

of_tableid_t
flow_entry_exec(struct flow_entry *flow, struct pl_pkt *pl_pkt, ev_tstamp now);

char *
flow_entry_to_string(struct flow_entry *entry);

uint16_t
flow_entry_prio(struct flow_entry *flow);

ev_tstamp
flow_entry_remove_at(struct flow_entry *flow);

#endif /* FLOW_ENTRY_H */
