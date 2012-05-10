/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef GROUP_TABLE_H
#define GROUP_TABLE_H 1

#include "lib/openflow.h"
#include "oflib/ofl_messages.h"

struct dp;
struct pl_pkt;
struct dp_msg;
struct group_table;
struct logger;

struct group_table *
group_table_new();

void
group_table_exec(struct group_table *table, struct pl_pkt *pl_pkt, of_groupid_t group_id);

ofl_err
group_table_group_mod(struct group_table *table, struct dp_msg *msg);

ofl_err
group_table_stats_group_desc(struct group_table *table, struct dp_msg *msg);

ofl_err
group_table_stats_group(struct group_table *table, struct dp_msg *msg);

bool
group_table_has(struct group_table *group_table, of_groupid_t group_id);

void
group_table_add_flow_ref(struct group_table *group_table, of_groupid_t group_id, uint32_t flow_ref);

void
group_table_del_flow_ref(struct group_table *group_table, of_groupid_t group_id, uint32_t flow_ref);

struct logger *
group_table_get_logger(struct group_table *group_table);


#endif /* GROUP_TABLE_H */
