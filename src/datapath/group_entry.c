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
 * Represents a group entry (all four defined types).
 */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include "oflib/ofl_messages.h"
#include "oflib/ofl_structs.h"
#include "oflib/ofl.h"
#include "logger/logger.h"
#include "lib/openflow.h"
#include "lib/util.h"
#include "lib/pkt_buf.h"
#include "dp.h"
#include "dp_int.h"
#include "action.h"
#include "action_list.h"
#include "action_set.h"
#include "pipeline_packet.h"
#include "group_entry.h"

//Note: a flow ref cannot start with 0xff
#define FLOW_REF_NO      0xffffff00
#define FLOW_REF_NO_MORE 0xffffffff

struct group_entry {
    struct dp_loop               *dp_loop;
    struct ofl_group_desc_stats  *desc;
    struct ofl_group_stats       *stats;
    uint32_t                    (*flow_refs)[];       /* list of flow unique IDs, which are referencing the group.
                                                         FLOW_REF_NO is used to represent an unused entry.
                                                         FLOW_REF_NO_MORE is used to represent no more entries.*/
    size_t                        flow_refs_size;
    size_t                        flow_refs_num;
    void                         *private;    /* private data for group implementation. */
};


/* Private data for select groups; for implementing weighted round-robin. */
struct wrr_data {
    uint16_t max_weight;  /* maximum weight of the buckets. */
    uint16_t gcd_weight;  /* g.c.d. of bucket weights. */
    uint16_t curr_weight; /* current weight in w.r.r. algorithm. */
    size_t   curr_bucket; /* bucket executed last time. */
};

/* Returns the number of buckets in the group. */
size_t
group_entry_buckets_num(struct group_entry *group) {
    return group->desc->buckets_num;
}

/* Returns a reference to the list of buckets in the group. */
struct ofl_bucket **
group_entry_buckets(struct group_entry *group) {
    return group->desc->buckets;
}

/* Tells whether the flow references contain the given flow unique id. */
static bool
has_flow_ref(struct group_entry *group, uint32_t flow_ref) {
    size_t i;
    for (i=0; i < group->flow_refs_size; i++) {
        if ((*(group->flow_refs))[i] == flow_ref) {
            return true;
        }
        if ((*(group->flow_refs))[i] == FLOW_REF_NO_MORE) {
            return false;
        }
    }
    return false;
}

/* Adds the given flow unique ID to the references (if not there yet). */
void
group_entry_add_flow_ref(struct group_entry *group, uint32_t flow_ref) {
    if (has_flow_ref(group, flow_ref)) {
        return;
    }

    if (group->flow_refs_num == group->flow_refs_size) {
        size_t new_size = group->flow_refs_size * 2;
        group->flow_refs = realloc(group->flow_refs, new_size);
        size_t i;
        for (i=group->flow_refs_size; i < new_size; i++) {
            (*(group->flow_refs))[i] = FLOW_REF_NO_MORE;
        }
        group->flow_refs_size = new_size;
    } else {
        size_t i = 0;
        for (i=0; i < group->flow_refs_size; i++) {
            if ((*(group->flow_refs))[i] == FLOW_REF_NO || (*(group->flow_refs))[i] == FLOW_REF_NO_MORE) {
                (*(group->flow_refs))[i] = flow_ref;
                break;
            }
        }
        assert(i <= group->flow_refs_num); // must have found a place by then
    }
    group->flow_refs_num++;
    group->stats->ref_count++;
}

/* Removes the given flow unique ID from the references. */
void
group_entry_del_flow_ref(struct group_entry *group, uint32_t flow_ref) {
    size_t i;
    for (i=0; i < group->flow_refs_size; i++) {
        if ((*(group->flow_refs))[i] == flow_ref) {
            (*(group->flow_refs))[i] = FLOW_REF_NO;
            return;
        }
        if ((*(group->flow_refs))[i] == FLOW_REF_NO_MORE) {
            return;
        }
    }
}

/* Returns the g.c.d. of the two numbers. */
static CONST_ATTR uint16_t
gcd(uint16_t a, uint16_t b) {
    uint16_t c;

    while (a != 0) {
        c = a;
        a = b % a;
        b = c;
    }

    return b;
}

/* Initializes the private w.r.r. data for a select group entry. */
static void
init_select(struct group_entry *group, struct ofl_msg_group_mod *mod) {
    struct wrr_data *wrr = malloc(sizeof(struct wrr_data));

    wrr->curr_weight = 0;
    wrr->curr_bucket = -1;

    if (mod->buckets_num == 0) {
        wrr->gcd_weight = 0;
        wrr->max_weight = 0;
    } else {
        wrr->gcd_weight = group->desc->buckets[0]->weight;
        wrr->max_weight = group->desc->buckets[0]->weight;

        size_t i;
        for (i=1; i< group->desc->buckets_num; i++) {
            wrr->gcd_weight = gcd(wrr->gcd_weight, group->desc->buckets[i]->weight);
            wrr->max_weight = MAX(wrr->max_weight, group->desc->buckets[i]->weight);
        }

    }

    group->private = wrr;
}

/* Creates a new group entry. */
struct group_entry * MALLOC_ATTR
group_entry_new(struct dp_loop *dp_loop, struct ofl_msg_group_mod *mod) {
    struct group_entry *group = malloc(sizeof(struct group_entry));

    group->dp_loop = dp_loop;

    group->desc = malloc(sizeof(struct ofl_group_desc_stats));
    group->desc->type =        mod->type;
    group->desc->group_id =    mod->group_id;
    group->desc->buckets_num = mod->buckets_num;
    group->desc->buckets     = mod->buckets;

    group->stats = malloc(sizeof(struct ofl_group_stats));
    group->stats->group_id      = mod->group_id;
    group->stats->ref_count     = 0;
    group->stats->packet_count  = 0;
    group->stats->byte_count    = 0;
    group->stats->counters_num  = mod->buckets_num;
    group->stats->counters      = malloc(sizeof(struct ofl_bucket_counter *) * mod->buckets_num);

    size_t i;
    for (i=0; i<mod->buckets_num; i++) {
        group->stats->counters[i] = malloc(sizeof(struct ofl_bucket_counter));
        group->stats->counters[i]->packet_count = 0;
        group->stats->counters[i]->byte_count = 0;
    }

    switch (mod->type) {
        case (OFPGT_SELECT): {
            init_select(group, mod);
            break;
        }
        default: {
            group->private = NULL;
            break;
        }
    }

    group->flow_refs = malloc(sizeof(uint32_t) * 16);
    for (i=0; i < 16; i++) {
        (*(group->flow_refs))[i] = FLOW_REF_NO_MORE;
    }
    group->flow_refs_size = 16;
    group->flow_refs_num = 0;

    return group;
}

/* Frees a group entry. */
void
group_entry_free(struct group_entry *group) {
    size_t i;
    for (i=0; i < group->flow_refs_size; i++) {
        if ((*(group->flow_refs))[i] == FLOW_REF_NO_MORE) {
            break;
        }
        if ((*(group->flow_refs))[i] != FLOW_REF_NO) {
            dp_pl_flow_remove_by_ref(group->dp_loop, (*(group->flow_refs))[i]);
        }
    }

    ofl_structs_free_group_desc_stats(group->desc, OFL_NO_EXP, NULL/*errbuf*/);
    ofl_structs_free_group_stats(group->stats);
    free(group->flow_refs);
    free(group->private);
    free(group);
}

/* Replaces the buckets of the given group entry. */
void
group_entry_replace_buckets(struct group_entry *group, size_t buckets_num,
                          struct ofl_bucket **buckets) {
    /* TODO could be done more efficiently... */

    struct ofl_group_desc_stats *desc = malloc(sizeof(struct ofl_group_desc_stats));
    desc->type =        group->desc->type;
    desc->group_id =    group->desc->group_id;
    desc->buckets_num = buckets_num;
    desc->buckets     = buckets;

    struct ofl_group_stats *stats = malloc(sizeof(struct ofl_group_stats));
    stats->group_id      = group->stats->group_id;
    stats->ref_count     = 0;
    stats->packet_count  = 0;
    stats->byte_count    = 0;
    stats->counters_num  = desc->buckets_num;
    stats->counters      = malloc(sizeof(struct ofl_bucket_counter *) * desc->buckets_num);

    size_t i;
    for (i=0; i<desc->buckets_num; i++) {
        stats->counters[i] = malloc(sizeof(struct ofl_bucket_counter));
        stats->counters[i]->packet_count = 0;
        stats->counters[i]->byte_count = 0;
    }

    ofl_structs_free_group_desc_stats(group->desc, OFL_NO_EXP, NULL/*errbuf*/);
    ofl_structs_free_group_stats(group->stats);

    group->desc = desc;
    group->stats = stats;
}

/* Returns a copy of the group entry's desc stats. */
struct ofl_group_desc_stats *
group_entry_desc_stats(struct group_entry *group) {
    struct ofl_group_desc_stats *desc = memcpy(malloc(sizeof(struct ofl_group_desc_stats)),
                                               group->desc, sizeof(struct ofl_group_desc_stats));

    desc->buckets = malloc(sizeof(struct ofl_bucket *) * desc->buckets_num);
    size_t i;
    for (i=0; i<desc->buckets_num; i++) {
        desc->buckets[i] = ofl_structs_bucket_clone(group->desc->buckets[i], OFL_NO_EXP, NULL/*errbuf*/);
    }

    return desc;
}

/* Returns a copy of the group entry's stats. */
struct ofl_group_stats *
group_entry_stats(struct group_entry *group) {
    struct ofl_group_stats *stats = memcpy(malloc(sizeof(struct ofl_group_stats)),
                                         group->stats, sizeof(struct ofl_group_stats));
    stats->counters = malloc(sizeof(struct ofl_bucket_counter *) * stats->counters_num);
    size_t i;
    for (i=0; i<stats->counters_num; i++) {
        stats->counters[i] = memcpy(malloc(sizeof(struct ofl_bucket_counter)),
                                    group->stats->counters[i], sizeof(struct ofl_bucket_counter));
    }

    return stats;
}

/* Tells whether the group entry outputs to the given group entry. */
bool
group_entry_has_out_group(struct group_entry *group, of_groupid_t group_id) {
    size_t i;
    for (i=0; i<group->desc->buckets_num; i++) {
        struct ofl_bucket *b = (struct ofl_bucket *)(group->desc->buckets[i]);
        if (action_list_has_out_group(b->actions, b->actions_num, group_id)) {
            return true;
        }
    }
    return false;
}


/* Executes a group entry of type ALL. */
static void
exec_all(struct group_entry *entry, struct pl_pkt *pl_pkt) {
    /* TODO Currently packets are always cloned. However it should
     * be possible to see if cloning is necessary, or not, based on bucket actions. */

    size_t i;
    for (i=0; i<entry->desc->buckets_num; i++) {
        struct ofl_bucket *bucket = entry->desc->buckets[i];
        struct pl_pkt *clone = pl_pkt_clone(pl_pkt);

        if (logger_is_enabled(pl_pkt->logger, LOG_DEBUG)) {
            char *b = ofl_structs_bucket_to_string(bucket, OFL_NO_EXP);
            logger_log(pl_pkt->logger, LOG_DEBUG, "Writing bucket: %s.", b);
            free(b);
        }

        action_set_write_acts(clone->act_set, bucket->actions, bucket->actions_num);

        entry->stats->byte_count += clone->pkt->data_len;
        entry->stats->packet_count++;
        entry->stats->counters[i]->byte_count += clone->pkt->data_len;
        entry->stats->counters[i]->packet_count++;

        action_set_exec(entry->dp_loop, clone->act_set, clone);
        pl_pkt_free(clone, true);
    }
}

static ssize_t
select_from_select_group(struct group_entry *entry, struct pl_pkt *pl_pkt);

/* Executes a group entry of type SELECT. */
static void
exec_select(struct group_entry *entry, struct pl_pkt *pl_pkt) {
    ssize_t b  = select_from_select_group(entry, pl_pkt);

    if (b != -1) {
        struct ofl_bucket *bucket = entry->desc->buckets[b];
        struct pl_pkt *clone = pl_pkt_clone(pl_pkt);

        if (logger_is_enabled(pl_pkt->logger, LOG_DEBUG)) {
            char *b = ofl_structs_bucket_to_string(bucket, OFL_NO_EXP);
            logger_log(pl_pkt->logger, LOG_DEBUG, "Writing bucket: %s.", b);
            free(b);
        }

        action_set_write_acts(clone->act_set, bucket->actions, bucket->actions_num);

        entry->stats->byte_count += pl_pkt->pkt->data_len;
        entry->stats->packet_count++;
        entry->stats->counters[b]->byte_count += pl_pkt->pkt->data_len;
        entry->stats->counters[b]->packet_count++;

        action_set_exec(entry->dp_loop, clone->act_set, clone);
        pl_pkt_free(clone, true);
    } else {
        logger_log(pl_pkt->logger, LOG_DEBUG, "No bucket in group.");
    }
}

/* Execute a group entry of type INDIRECT. */
static void
exec_indirect(struct group_entry *entry, struct pl_pkt *pl_pkt) {
    if (entry->desc->buckets_num > 0) {
        struct ofl_bucket *bucket = entry->desc->buckets[0];
        struct pl_pkt *clone = pl_pkt_clone(pl_pkt);

        if (logger_is_enabled(pl_pkt->logger, LOG_DEBUG)) {
            char *b = ofl_structs_bucket_to_string(bucket, OFL_NO_EXP);
            logger_log(pl_pkt->logger, LOG_DEBUG, "Writing bucket: %s.", b);
            free(b);
        }

        action_set_write_acts(clone->act_set, bucket->actions, bucket->actions_num);

        entry->stats->byte_count += pl_pkt->pkt->data_len;
        entry->stats->packet_count++;
        entry->stats->counters[0]->byte_count += pl_pkt->pkt->data_len;
        entry->stats->counters[0]->packet_count++;

        action_set_exec(entry->dp_loop, clone->act_set, clone);
        pl_pkt_free(clone, true);
    } else {
        logger_log(pl_pkt->logger, LOG_DEBUG, "No bucket in group.");
    }
}

static ssize_t
select_from_ff_group(struct group_entry *entry);

/* Execute a group entry of type FAILFAST. */
static void
exec_ff(struct group_entry *entry, struct pl_pkt *pl_pkt) {
    ssize_t b  = select_from_ff_group(entry);

    if (b != -1) {
        struct ofl_bucket *bucket = entry->desc->buckets[b];
        struct pl_pkt *clone = pl_pkt_clone(pl_pkt);

        if (logger_is_enabled(pl_pkt->logger, LOG_DEBUG)) {
            char *b = ofl_structs_bucket_to_string(bucket, OFL_NO_EXP);
            logger_log(pl_pkt->logger, LOG_DEBUG, "Writing bucket: %s.", b);
            free(b);
        }

        action_set_write_acts(clone->act_set, bucket->actions, bucket->actions_num);

        entry->stats->byte_count += pl_pkt->pkt->data_len;
        entry->stats->packet_count++;
        entry->stats->counters[b]->byte_count += pl_pkt->pkt->data_len;
        entry->stats->counters[b]->packet_count++;

        action_set_exec(entry->dp_loop, clone->act_set, clone);
        pl_pkt_free(clone, true);
    } else {
        logger_log(pl_pkt->logger, LOG_DEBUG, "No bucket in group.");
    }
}


/* Executes the given group entry. */
void
group_entry_exec(struct group_entry *entry,  struct pl_pkt *pl_pkt) {
    logger_log(pl_pkt->logger, LOG_DEBUG, "Executing group %u.", entry->stats->group_id);
    /* NOTE: Packet is copied for all buckets now (even if there is only one).
     * This allows execution of the original packet onward. It is not clear
     * whether that is allowed or not according to the spec. though. */

    switch (entry->desc->type) {
        case (OFPGT_ALL): {
            exec_all(entry, pl_pkt);
            break;
        }
        case (OFPGT_SELECT): {
            exec_select(entry, pl_pkt);
            break;
        }
        case (OFPGT_INDIRECT): {
            exec_indirect(entry, pl_pkt);
            break;
        }
        case (OFPGT_FF): {
            exec_ff(entry, pl_pkt);
            break;
        }
        default: {
            logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute unknown group type (%u) in group (%u).", entry->desc->type, entry->stats->group_id);
            break;
        }
    }
}

/* Returns true if the bucket is alive. */
static bool
bucket_is_alive(struct ofl_bucket *bucket UNUSED_ATTR) {
    // TODO Implement port up/down detection
    return true;
}


/* Selects a bucket from a select group, based on the w.r.r. algorithm. */
static ssize_t
select_from_select_group(struct group_entry *entry, struct pl_pkt *pl_pkt) {
    if (entry->desc->buckets_num == 0) {
        return -1;
    }

    struct wrr_data *data = (struct wrr_data *)entry->private;

    size_t guard = 0;
    while (guard < entry->desc->buckets_num) {
        data->curr_bucket = (data->curr_bucket + 1) % entry->desc->buckets_num;

        if (data->curr_bucket == 0) {
            if (data->curr_weight <= data->gcd_weight) {
                data->curr_weight = data->max_weight;
            } else {
                data->curr_weight = data->curr_weight - data->gcd_weight;
            }
        }

        if (entry->desc->buckets[data->curr_bucket]->weight >= data->curr_weight) {
            return data->curr_bucket;
        }
        guard++;
    }
    logger_log(pl_pkt->logger, LOG_ERR, "Could not select from select group.");
    return -1;
}

/* Selects the first live bucket from the failfast group. */
static ssize_t
select_from_ff_group(struct group_entry *entry) {
    size_t i;

    for (i=0; i<entry->desc->buckets_num; i++) {
        if (bucket_is_alive(entry->desc->buckets[i])) {
            return i;
        }
    }
    return -1;
}

