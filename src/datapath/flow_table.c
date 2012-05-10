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
 * Represents a flow table.
 */

#include <ev.h>
#include <uthash/uthash.h>
#include <uthash/utlist.h>
#include "logger/logger.h"
#include "logger/logger_mgr.h"
#include "lib/openflow.h"
#include "lib/list.h"
#include "lib/logger_names.h"
#include "oflib/ofl_structs.h"
#include "action_set.h"
#include "flow_table.h"
#include "flow_entry.h"
#include "dp.h"
#include "capabilities.h"
#include "pipeline_packet.h"
#include "dp_int.h"
#include "lib/pkt_buf.h"

#define MAX_ENTRIES   4096


/* Structure for storing flow entries in various containers. */
struct flow_e {
    struct list_node       entry_node;
    struct list_node       idle_node;
    struct list_node       hard_node;
    UT_hash_handle    hh;

    uint32_t          uid;
    struct flow_entry  *entry;
    bool              hard_to;
    bool              idle_to;

};

struct flow_table {
    struct dp_loop *dp_loop;
    struct logger *logger;

    struct flow_e  *flow_map;  /* map of entries based on their unique ID. */
    struct list_node  *flow_list; /* list of entries in prio/insert order. */
    struct list_node  *hard_list; /* list of hard-to entries in timeout order. */
    struct list_node  *idle_list; /* arbitrary list of idle-to entries. */

    struct ofl_table_stats  *stats;  /* structure storing table statistics. */

    uint32_t       next_flow_uid;
};

/* Creates a new flow table. */
struct flow_table * MALLOC_ATTR
flow_table_new(struct dp_loop *dp_loop, of_tableid_t id) {
    struct flow_table *flow_table = malloc(sizeof(struct flow_table));
    flow_table->dp_loop = dp_loop;
    flow_table->logger = logger_mgr_get(LOGGER_NAME_DP_FLOWTABLE, dp_loop_get_uid(dp_loop), id);

    flow_table->flow_map = NULL;
    flow_table->flow_list = NULL;
    flow_table->hard_list = NULL;
    flow_table->idle_list = NULL;

    flow_table->stats = malloc(sizeof(struct ofl_table_stats));
    flow_table->stats->table_id      = id;
    flow_table->stats->name          = malloc(OFP_MAX_TABLE_NAME_LEN + 1);
    snprintf(flow_table->stats->name, OFP_MAX_TABLE_NAME_LEN, "table_%u", id);
    flow_table->stats->name[OFP_MAX_TABLE_NAME_LEN] = '\0';
    flow_table->stats->wildcards     = DP_WILDCARDS;
    flow_table->stats->match         = DP_MATCH_FIELDS;
    flow_table->stats->instructions  = DP_INSTRUCTIONS;
    flow_table->stats->write_actions = DP_ACTIONS;
    flow_table->stats->apply_actions = DP_ACTIONS;
    flow_table->stats->config        = OFPTC_TABLE_MISS_CONTROLLER;
    flow_table->stats->max_entries   = MAX_ENTRIES;
    flow_table->stats->active_count  = 0;
    flow_table->stats->lookup_count  = 0;
    flow_table->stats->matched_count = 0;

    /* Note: Flow unique identifiers have the following structure:
     * upper 8bit represents the table id, lower 24 bits is a counter. */
    flow_table->next_flow_uid = (id << 24);

    return flow_table;
}

/* Insert a flow entry to the hard timeout list. */
static void
insert_hard_to(struct flow_table *table, struct flow_e *flow_e) {
    ev_tstamp remove_at = flow_entry_remove_at(flow_e->entry);

    struct list_node *node;
    DL_FOREACH(table->hard_list, node) {
        struct flow_e *e = CONTAINER_OF(node, struct flow_e, hard_node);
        if (flow_entry_remove_at(e->entry) > remove_at) {
            logger_log(table->logger, LOG_DEBUG, "lower timeout entry found (%u), prepending flow %u.", e->uid & 0x00ffffff, flow_e->uid & 0x00ffffff);
            DL_PREPEND_ELEM(table->hard_list, node, &(flow_e->hard_node));
            return;
        }
    }

    logger_log(table->logger, LOG_DEBUG, "appending (appending prepending flow %u to hard_to.", flow_e->uid & 0x00ffffff);
    DL_APPEND(table->hard_list, &(flow_e->hard_node));
}

/* Handles flow mod messages with ADD command. */
static ofl_err
mod_add(struct flow_table *table, struct ofl_msg_flow_mod *msg, bool *match_kept, bool *insts_kept) {
    logger_log(table->logger, LOG_DEBUG, "mod_add called.");

    // Note: new entries will be placed behind those with equal priority
    if (table->stats->active_count == MAX_ENTRIES) { // TODO what if this replaces an old one?
        logger_log(table->logger, LOG_INFO, "Table full.");
        return ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_TABLE_FULL);
    }

    if ((msg->flags & OFPFF_CHECK_OVERLAP) != 0) {
        struct list_node *list;
        DL_FOREACH(table->flow_list, list) {
            struct flow_e *e = CONTAINER_OF(list, struct flow_e, entry_node);
            if (flow_entry_overlaps(e->entry, msg)) {
                logger_log(table->logger, LOG_INFO, "Found overlapping entry (%u).", e->uid);
                return ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_OVERLAP);
            }
        }
    }


    uint32_t flow_uid = table->next_flow_uid;
    table->next_flow_uid++;
    // note 0xff is not a valid table id, so complete overflow is not possible
    if ((table->next_flow_uid & 0x00ffffff) == 0) {
        table->next_flow_uid = (table->stats->table_id << 24);
        logger_log(table->logger, LOG_INFO, "Flow uid overflow.");
    }

    struct flow_e *new_e = malloc(sizeof(struct flow_e));
    new_e->uid = flow_uid;
    new_e->entry = flow_entry_new(table, flow_uid, msg, dp_loop_now(table->dp_loop));
    HASH_ADD_KEYPTR(hh, table->flow_map, &(new_e->uid), sizeof(uint32_t), new_e);

    new_e->hard_to = (msg->hard_timeout != 0);
    if (new_e->hard_to) {
        insert_hard_to(table, new_e);
    }

    new_e->idle_to = (msg->idle_timeout != 0);
    if (new_e->idle_to) {
        DL_APPEND(table->idle_list, &(new_e->idle_node));
    }

    bool placed = false;
    struct list_node *node;
    DL_FOREACH(table->flow_list, node) {
        struct flow_e *e = CONTAINER_OF(node, struct flow_e, entry_node);
        /* if the entry equals, remove the old one */
        if (flow_entry_matches_mod(e->entry, msg, true/*strict*/, false/*check_cookie*/)) {
            logger_log(table->logger, LOG_DEBUG, "matching flow entry found (%u), replacing it with new flow entry %u.", e->uid & 0x00ffffff, new_e->uid & 0x00ffffff);

            HASH_DEL(table->flow_map, e);
            if (e->hard_to) {
                DL_DELETE(table->hard_list, &(e->hard_node));
            }
            if (e->idle_to) {
                DL_DELETE(table->idle_list, &(e->idle_node));
            }

            DL_REPLACE_ELEM(table->flow_list, &(e->entry_node), &(new_e->entry_node));
            /* NOTE: no flow removed message should be generated according to spec. */
            flow_entry_free(e->entry, true/*free_stats*/);
            free(e);
            table->stats->active_count--;

            placed = true;
            break;
        }

        if (msg->priority > flow_entry_prio(e->entry)) {
            logger_log(table->logger, LOG_DEBUG, "lower priority flow entry found (%u), prepending it with new flow entry %u.", e->uid & 0x00ffffff, new_e->uid & 0x00ffffff);
            DL_PREPEND_ELEM(table->flow_list, &(e->entry_node), &(new_e->entry_node));

            placed = true;
            break;
        }
    }

    table->stats->active_count++; // only if replace = false

    if (!placed) {
        logger_log(table->logger, LOG_DEBUG, "appending new flow entry %u.", new_e->uid & 0x00ffffff);
        DL_APPEND(table->flow_list, &(new_e->entry_node));
    }

    *match_kept = true;
    *insts_kept = true;

    logger_log(table->logger, LOG_DEBUG, "Added new flow: %d.", flow_uid);

    return 0;
}


/* Handles flow mod messages with MODIFY command. */
static ofl_err
mod_modify(struct flow_table *table, struct ofl_msg_flow_mod *msg, bool strict, bool *match_kept, bool *insts_kept) {
    logger_log(table->logger, LOG_DEBUG, "mod_modify called.");

    bool found = false;

    struct list_node *node;
    DL_FOREACH(table->flow_list, node) {
        struct flow_e *e = CONTAINER_OF(node, struct flow_e, entry_node);
        if (flow_entry_matches_mod(e->entry, msg, strict, true/*check cookie*/)) {
            //note: replace must copy as multiple flows might be modified
            logger_log(table->logger, LOG_DEBUG, "found matching entry (%u); replacing instructions.", e->uid & 0x00ffffff);
            flow_entry_replace_instructions(e->entry, msg->instructions_num, msg->instructions);
            found = true;
        }
    }

    if (found) {
        //instructions were copied, match_kept, insts_kept remain false
        return 0;
    }

    /* NOTE: if modify does not modify any entries, it acts like an add according to spec. */
    return mod_add(table, msg, match_kept, insts_kept);
}

/* Removes a flow entry with the given reason. */
static void
remove_flow(struct flow_table *table, struct flow_e *e, enum ofp_flow_removed_reason reason) {
    logger_log(table->logger, LOG_DEBUG, "removing flow %u.", e->uid & 0x00ffffff);

    HASH_DEL(table->flow_map, e);
    if (e->hard_to) {
        DL_DELETE(table->hard_list, &(e->hard_node));
    }
    if (e->idle_to) {
        DL_DELETE(table->idle_list, &(e->idle_node));
    }
    DL_DELETE(table->flow_list, &(e->entry_node));
    flow_entry_remove(table->dp_loop, e->entry, reason);
    free(e);
}

/* Handles flow mod messages with DELETE command. */
static ofl_err
mod_delete(struct flow_table *table, struct ofl_msg_flow_mod *msg, bool strict) {
    if (table->flow_list == NULL) {
        return 0;
    }

    logger_log(table->logger, LOG_DEBUG, "mod_delete called.");

    struct list_node *node, *next;
    DL_FOREACH_SAFE(table->flow_list, node, next) {
        struct flow_e *e = CONTAINER_OF(node, struct flow_e, entry_node);
        if (flow_entry_matches_mod(e->entry, msg, strict, true/*check cookie*/)) {
            remove_flow(table, e, OFPRR_DELETE);
            table->stats->active_count--;
        }
    }
    return 0;
}

/* Handles flow_mod messages destined at this flow table. */
ofl_err
flow_table_flow_mod(struct flow_table *table, struct ofl_msg_flow_mod *msg, bool *match_kept, bool *insts_kept) {
    switch (msg->command) {
        case (OFPFC_ADD): {
            return mod_add(table, msg, match_kept, insts_kept);
        }
        case (OFPFC_MODIFY): {
            return mod_modify(table, msg, false, match_kept, insts_kept);
        }
        case (OFPFC_MODIFY_STRICT): {
            return mod_modify(table, msg, true, match_kept, insts_kept);
        }
        case (OFPFC_DELETE): {
            return mod_delete(table, msg, false);
        }
        case (OFPFC_DELETE_STRICT): {
            return mod_delete(table, msg, true);
        }
        default: {
            return ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_COMMAND);
        }
    }

    return 0;
}

/* Returns a copy of the table's statistics. */
struct MALLOC_ATTR ofl_table_stats *
flow_table_stats(struct flow_table *table) {
    struct ofl_table_stats *stats = memcpy(malloc(sizeof(struct ofl_table_stats)),
                                           table->stats, sizeof(struct ofl_table_stats));

    stats->name = strdup(table->stats->name);
    return stats;
}

/* Modifies the config of the flow_table. */
void
flow_table_mod(struct flow_table *table, uint32_t config) {
    table->stats->config = config;
}

/* Requests flow statistics from the given table. */
void
flow_table_stats_flow(struct flow_table *table, struct ofl_msg_stats_request_flow *msg,
                 struct ofl_flow_stats ***stats, size_t *stats_size, size_t *stats_num) {
    ev_tstamp now = dp_loop_now(table->dp_loop);

    struct list_node *node;
    DL_FOREACH(table->flow_list, node) {
        struct flow_e *e = CONTAINER_OF(node, struct flow_e, entry_node);
        if (flow_entry_matches_stat(e->entry, msg)) {
            if ((*stats_size) == (*stats_num)) {
                (*stats) = realloc(*stats, (sizeof(struct ofl_flow_stats *)) * (*stats_size) * 2);
                *stats_size *= 2;
            }
            (*stats)[(*stats_num)] = flow_entry_stats(e->entry, now);
            (*stats_num)++;
        }
    }
}

/* Requests flow aggregate statistics from the given table. */
struct flow_table_aggr
flow_table_stats_aggr(struct flow_table *table, struct ofl_msg_stats_request_flow *msg) {
    struct flow_table_aggr aggr = {
        .packet_count = 0,
        .byte_count = 0,
        .flow_count = 0
    };

    struct list_node *node;
    DL_FOREACH(table->flow_list, node) {
        struct flow_e *e = CONTAINER_OF(node, struct flow_e, entry_node);
        if (flow_entry_matches_stat(e->entry, msg)) {
            struct flow_aggr flow_aggr = flow_entry_stats_aggr(e->entry);
            aggr.packet_count += flow_aggr.packet_count;
            aggr.byte_count   += flow_aggr.byte_count;
            aggr.flow_count   += 1;
        }
    }

    return aggr;
}


/* Requests the table to check and clean timed out flows. */
void
flow_table_timeout(struct flow_table *table, ev_tstamp now) {
    /* NOTE: hard timeout entries are ordered by the time they should be removed at,
     * so if one is not removed, the rest will not be either. */
    struct list_node *node, *next;
    DL_FOREACH_SAFE(table->hard_list, node, next) {
        struct flow_e *e = CONTAINER_OF(node, struct flow_e, hard_node);
        if (flow_entry_hard_timeout(e->entry, now)) {
            remove_flow(table, e, OFPRR_HARD_TIMEOUT);
        } else {
            break;
        }
    }

    DL_FOREACH_SAFE(table->idle_list, node, next) {
        struct flow_e *e = CONTAINER_OF(node, struct flow_e, idle_node);
        if (flow_entry_idle_timeout(e->entry, now)) {
            remove_flow(table, e, OFPRR_IDLE_TIMEOUT);
        }
    }
}

/* Requests the table to find the matching entry and execute it, or execute
 * the table config otherwise.
 * Returns the next table-id if that table should be consulted, or 0xff otherwise. */
of_tableid_t
flow_table_exec(struct flow_table *table, struct pl_pkt *pl_pkt, ev_tstamp now) {
    table->stats->lookup_count++;

    struct flow_entry *entry = NULL;

    struct list_node *node;
    DL_FOREACH(table->flow_list, node) {
        struct flow_e *e = CONTAINER_OF(node, struct flow_e, entry_node);
        logger_log(table->logger, LOG_DEBUG, "Trying flow %d", e->uid & 0x00ffffff);

        if (flow_entry_matches_pkt(e->entry, pl_pkt)) {
            table->stats->matched_count++;
            entry = e->entry;
            break;
        }
    }

    if (entry != NULL) {
        if (logger_is_enabled(table->logger, LOG_DEBUG)) {
            char *str = flow_entry_to_string(entry);
            logger_log(table->logger, LOG_DEBUG, "found matching entry: %s.", str);
            free(str);
        }

        return flow_entry_exec(entry, pl_pkt, now);
    } else {
        // exec table conf
        logger_log(table->logger, LOG_DEBUG, "no matching entry found. executing table conf.");
        if ((table->stats->config & OFPTC_TABLE_MISS_CONTINUE) != 0) {
            return (table->stats->table_id + 1);
        } else if ((table->stats->config & OFPTC_TABLE_MISS_DROP) != 0) {
            logger_log(table->logger, LOG_DEBUG, "Table set to drop packet.");
            //clearing action set to drop packet
            action_set_clear(pl_pkt->act_set);
            return OF_ALL_TABLE;
        } else { // OFPTC_TABLE_MISS_CONTROLLER
            dp_pl_pkt_to_ctrl(table->dp_loop, pl_pkt->pkt->data_len, pl_pkt, OFPR_NO_MATCH);
            action_set_clear(pl_pkt->act_set);
            return OF_ALL_TABLE;
        }
    }
}

/* Removes the flow entry with the given unique id. */
void
flow_table_remove_by_ref(struct flow_table *flow_table, uint32_t flow_ref) {
    struct flow_e *e;
    HASH_FIND(hh, flow_table->flow_map, &flow_ref, sizeof(uint32_t), e);

    if (e != NULL) {
        remove_flow(flow_table, e, OFPRR_GROUP_DELETE);
    }

}

/* Returns the DP structure of the given flow table. */
struct dp_loop *
flow_table_get_dp_loop(struct flow_table *flow_table) {
    return flow_table->dp_loop;
}

/* Returns the logger of the flow_table (to be used by entries). */
struct logger *
flow_table_get_logger(struct flow_table *flow_table) {
    return flow_table->logger;
}
