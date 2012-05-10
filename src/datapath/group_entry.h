/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef GROUP_ENTRY_H
#define GROUP_ENTRY_H 1


#include "oflib/ofl_messages.h"

struct group_entry;
struct dp_loop;

size_t
group_entry_buckets_num(struct group_entry *group);

struct ofl_bucket **
group_entry_buckets(struct group_entry *group);

void
group_entry_add_flow_ref(struct group_entry *group, uint32_t flow_ref);

void
group_entry_del_flow_ref(struct group_entry *group, uint32_t flow_ref);


struct group_entry *
group_entry_new(struct dp_loop *dp_loop, struct ofl_msg_group_mod *mod);

void
group_entry_free(struct group_entry *group);

void
group_entry_replace_buckets(struct group_entry *group, size_t buckets_num,
                          struct ofl_bucket **buckets);

struct ofl_group_desc_stats *
group_entry_desc_stats(struct group_entry *group);

struct ofl_group_stats *
group_entry_stats(struct group_entry *group);

bool
group_entry_has_out_group(struct group_entry *group, of_groupid_t group_id);

void
group_entry_exec(struct group_entry *entry,  struct pl_pkt *pl_pkt);

#endif /* GROUP_ENTRY_H */
