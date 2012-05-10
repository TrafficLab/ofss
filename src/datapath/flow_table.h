/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H 1

#include <ev.h>
#include "lib/compiler.h"
#include "lib/openflow.h"
#include "oflib/ofl_messages.h"

struct dp;
struct pl_pkt;
struct flow_table;
struct logger;

struct flow_table_aggr {
    uint64_t   packet_count; /* Number of packets in flows. */
    uint64_t   byte_count;   /* Number of bytes in flows. */
    uint32_t   flow_count;   /* Number of flows. */
};

struct flow_table *
flow_table_new(struct dp_loop *dp_loop, of_tableid_t id);

ofl_err
flow_table_flow_mod(struct flow_table *table, struct ofl_msg_flow_mod *msg, bool *match_kept, bool *insts_kept);

void
flow_table_stats_flow(struct flow_table *table, struct ofl_msg_stats_request_flow *msg,
                 struct ofl_flow_stats ***stats, size_t *stats_size, size_t *stats_num);

struct ofl_table_stats *
flow_table_stats(struct flow_table *table);

void
flow_table_mod(struct flow_table *table, uint32_t config);

struct flow_table_aggr
flow_table_stats_aggr(struct flow_table *table, struct ofl_msg_stats_request_flow *msg);

struct flow_ent *
flow_table_lookup(struct flow_table *table, struct pl_pkt *pl_pkt);

void
flow_table_timeout(struct flow_table *table, ev_tstamp now);

of_tableid_t
flow_table_exec(struct flow_table *table, struct pl_pkt *pl_pkt, ev_tstamp now);

void
flow_table_remove_by_ref(struct flow_table *flow_tab, uint32_t flow_ref);

struct dp_loop *
flow_table_get_dp_loop(struct flow_table *flow_tab);

struct logger *
flow_table_get_logger(struct flow_table *flow_tab);

#endif /* FLOW_TABLE_H */
