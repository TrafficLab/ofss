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
 * Represents a flow entry.
 */

#include <assert.h>
#include <ev.h>
#include <stdbool.h>
#include <stddef.h>
#include "control/ctrl.h"
#include "logger/logger.h"
#include "lib/compiler.h"
#include "lib/openflow.h"
#include "lib/packets.h"
#include "lib/pkt_buf.h"
#include "oflib/ofl_structs.h"
#include "oflib/ofl_messages.h"
#include "oflib/ofl_utils.h"
#include "oflib/ofl.h"
#include "action.h"
#include "action_list.h"
#include "action_set.h"
#include "flow_entry.h"
#include "flow_table.h"
#include "dp.h"
#include "dp_int.h"
#include "dp_ctrl.h"
#include "pipeline_packet.h"
#include "match_standard.h"

struct flow_entry {
    struct flow_table       *table;
    uint32_t                 uid;
    struct logger           *logger;
    struct ofl_flow_stats   *stats;

    ev_tstamp                created;      /* time the entry was created at. */
    ev_tstamp                remove_at;    /* time the entry should be removed at
                                              due to its hard timeout. */
    ev_tstamp                last_used;    /* last time the flow entry matched a packet */
    bool                     send_removed; /* true if a flow removed should be sent
                                              when removing a flow. */

    uint32_t               (*group_refs)[];   /* list of group ids of groups which references
                                                 the flow.
                                                 OFPG_ALL is used to represent "no more entries".
                                                 OFPG_ANY is used to represent empty entries. */
    size_t                   group_refs_size;
    size_t                   group_refs_num;
};


/* Checks whether the group_refs array contains the given group_id. */
static bool
has_group_ref(struct flow_entry *entry, of_groupid_t group_id) {
    size_t i;
    for (i=0; i < entry->group_refs_size; i++) {
        if ((*(entry->group_refs))[i] == group_id) {
            return true;
        }
        if ((*(entry->group_refs))[i] == OFPG_ALL) {
            return false;
        }
    }
    return false;
}

/* Adds the given group_id to the group references (if not there yet). */
static bool
add_group_ref(struct flow_entry *entry, of_groupid_t group_id) {
    if (has_group_ref(entry, group_id)) {
        return false;
    }

    if (entry->group_refs_num == entry->group_refs_size) {
        size_t new_size = entry->group_refs_size * 2;
        entry->group_refs = realloc(entry->group_refs, new_size);
        size_t i;
        for (i=entry->group_refs_size; i < new_size; i++) {
            (*(entry->group_refs))[i] = OFPG_ALL;
        }
        (*(entry->group_refs))[entry->group_refs_num] = group_id;
        entry->group_refs_size = new_size;
    } else {
        size_t i = 0;
        for (i=0; i < entry->group_refs_size; i++) {
            if ((*(entry->group_refs))[i] == OFPG_ANY || (*(entry->group_refs))[i] == OFPG_ALL) {
                (*(entry->group_refs))[i] = group_id;
                break;
            }
        }
        assert(i <= entry->group_refs_num); // must have found a place by then
    }
    entry->group_refs_num++;
    return true;
}

/* Initializes the group references of the flow entry. */
static void
init_group_refs(struct flow_entry *entry) {
    size_t i;

    for (i=0; i<entry->stats->instructions_num; i++) {
        if (entry->stats->instructions[i]->type == OFPIT_APPLY_ACTIONS ||
            entry->stats->instructions[i]->type == OFPIT_WRITE_ACTIONS) {
            struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)entry->stats->instructions[i];

            size_t j;
            for (j=0; j < ia->actions_num; j++) {
                if (ia->actions[j]->type == OFPAT_GROUP) {
                    struct ofl_action_group *ag = (struct ofl_action_group *)(ia->actions[j]);
                    if (add_group_ref(entry, ag->group_id)) {
                        dp_pl_group_add_flow_ref(flow_table_get_dp_loop(entry->table), ag->group_id, entry->uid);
                    }
                }
            }
        }
    }
}

/* Deletes group references from the flow, and also deletes the flow references
 * from the referecenced groups. */
static void
del_group_refs(struct flow_entry *entry) {
    size_t i;
    for (i=0; i < entry->group_refs_size; i++) {
        if ((*(entry->group_refs))[i] == OFPG_ALL) {
            break;
        }
        if ((*(entry->group_refs))[i] != OFPG_ANY) {
            dp_pl_group_del_flow_ref(flow_table_get_dp_loop(entry->table), (*(entry->group_refs))[i], entry->uid);
        }
        (*(entry->group_refs))[i] = OFPG_ALL;
    }
}

/* Creates a new flow entry.
 * NOTE: keeps instructions and match structures from the incoming message
 */
struct flow_entry * MALLOC_ATTR
flow_entry_new(struct flow_table *flow_table, uint32_t uid, struct ofl_msg_flow_mod *mod, ev_tstamp now) {
    struct flow_entry *entry = malloc(sizeof(struct flow_entry));

    entry->table = flow_table;
    entry->uid = uid;
    entry->logger = flow_table_get_logger(flow_table);

    entry->stats = malloc(sizeof(struct ofl_flow_stats));
    entry->stats->table_id         = mod->table_id;
    entry->stats->duration_sec     = 0;
    entry->stats->duration_nsec    = 0;
    entry->stats->priority         = mod->priority;
    entry->stats->idle_timeout     = mod->idle_timeout;
    entry->stats->hard_timeout     = mod->hard_timeout;
    entry->stats->cookie           = mod->cookie;
    entry->stats->packet_count     = 0;
    entry->stats->byte_count       = 0;

    entry->stats->match            = mod->match;
    entry->stats->instructions_num = mod->instructions_num;
    entry->stats->instructions     = mod->instructions;

    entry->created      = now;
    entry->remove_at    = mod->hard_timeout == 0 ? 0
                                  : now + mod->hard_timeout;
    entry->last_used    = now;
    entry->send_removed = ((mod->flags & OFPFF_SEND_FLOW_REM) != 0);

    entry->group_refs = malloc(sizeof(of_groupid_t) * 16);
    size_t i;
    for (i=0; i < 16; i++) {
        (*(entry->group_refs))[i] = OFPG_ALL;
    }
    entry->group_refs_size = 16;
    entry->group_refs_num = 0;

    init_group_refs(entry);

    return entry;
}

/* Frees a flow entry. */
void
flow_entry_free(struct flow_entry *entry, bool free_stats) {

    // NOTE: This will be called when the group entry itself destroys the
    //       flow; but it won't be a problem.
    del_group_refs(entry);
    if (free_stats) {
        ofl_structs_free_flow_stats(entry->stats, OFL_NO_EXP, NULL/*errbuf*/);
    }
    free(entry->group_refs);
    free(entry);
}

/* Updates the statistics of the flow entry, before sending out the stats. */
static void
update(struct flow_entry *entry, ev_tstamp now) {
    // TODO is this calculation correct
    entry->stats->duration_sec  =  (int)(now - entry->created) / 1000;
    entry->stats->duration_nsec = ((int)(now - entry->created) % 1000) * 1000;
}

/* Removes the flow entry. The flow entry will be freed, and a flow_removed message
 * will be sent to the DP. */
void
flow_entry_remove(struct dp_loop *dp_loop, struct flow_entry *entry, uint8_t reason) {
    if (entry->send_removed) {
        update(entry, dp_loop_now(dp_loop));

        struct ofl_msg_flow_removed *msg = malloc(sizeof(struct ofl_msg_flow_removed));
        msg->header.type = OFPT_FLOW_REMOVED;
        msg->reason = reason;
        msg->stats = entry->stats;

        flow_entry_free(entry, false);
        dp_ctrl_send_msg(dp_loop, CTRL_CONN_ALL, 0/*XID*/, (struct ofl_msg_header *)msg);
    } else {
        flow_entry_free(entry, true);
    }
}

/* Tells whether the flow entry outputs to the given port. */
static bool
has_out_port(struct flow_entry *entry, of_port_no_t port) {
    size_t i;
    for (i=0; i<entry->stats->instructions_num; i++) {
        if (entry->stats->instructions[i]->type == OFPIT_APPLY_ACTIONS ||
            entry->stats->instructions[i]->type == OFPIT_WRITE_ACTIONS) {
            struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)entry->stats->instructions[i];

            if (action_list_has_out_port(ia->actions, ia->actions_num, port)) {
                return true;
            }
        }
    }
    return false;
}


/* Tells whether the flow entry outputs to the given group. */
static bool
has_out_group(struct flow_entry *entry, of_groupid_t group) {
    size_t i;
    for (i=0; i<entry->stats->instructions_num; i++) {
        if (entry->stats->instructions[i]->type == OFPIT_APPLY_ACTIONS ||
            entry->stats->instructions[i]->type == OFPIT_WRITE_ACTIONS) {
            struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)entry->stats->instructions[i];

            if (action_list_has_out_group(ia->actions, ia->actions_num, group)) {
                return true;
            }
        }
    }
    return false;
}

/* Tells whether the flow entry matches the given match entry. */
static bool
flow_entry_matches(struct flow_entry *entry, struct ofl_match_header *match, bool strict) {
    if (strict) {
        return match_std_strict((struct ofl_match_standard *)match,
                                (struct ofl_match_standard *)entry->stats->match);
    } else {
        return match_std_nonstrict((struct ofl_match_standard *)match,
                                   (struct ofl_match_standard *)entry->stats->match);
    }
}

/* Tells whether the flow entry matches the given flow_mod entry. */
bool
flow_entry_matches_mod(struct flow_entry *entry, struct ofl_msg_flow_mod *mod, bool strict, bool check_cookie) {
    if (check_cookie && ((entry->stats->cookie & mod->cookie_mask) != (mod->cookie & mod->cookie_mask))) {
        return false;
    }

    if (strict && (entry->stats->priority != mod->priority)) {
        return false;
    }

    if (mod->command == OFPFC_DELETE || mod->command == OFPFC_DELETE_STRICT) {
        if (mod->out_port != OFPP_ANY && !has_out_port(entry, mod->out_port)) {
            return false;
        }
        if (mod->out_group != OFPG_ANY && !has_out_group(entry, mod->out_group)) {
            return false;
        }
    }

    return flow_entry_matches(entry, mod->match, strict);
}

/* Tells whether the flow entry matches the given flow_stats request. */
bool
flow_entry_matches_stat(struct flow_entry *entry, struct ofl_msg_stats_request_flow *stat) {
    if ((entry->stats->cookie & stat->cookie_mask) != (stat->cookie & stat->cookie_mask)) {
        return false;
    }

    if (stat->out_port != OFPP_ANY && !has_out_port(entry, stat->out_port)) {
        return false;
    }
    if (stat->out_group != OFPG_ANY && !has_out_group(entry, stat->out_group)) {
        return false;
    }

    return flow_entry_matches(entry, stat->match, false/*strict*/);
}


/* Tells whether the flow entry matches the given packet. */
bool
flow_entry_matches_pkt(struct flow_entry *flow, struct pl_pkt *pl_pkt) {
    if (flow->stats->match->type == OFPMT_STANDARD) {
        return match_std_pkt((struct ofl_match_standard *)(flow->stats->match), pl_pkt);
    } else {
        return false;
    }
}

/* Tells whether the flow entry overlaps with the given flow_mod. */
bool
flow_entry_overlaps(struct flow_entry *entry, struct ofl_msg_flow_mod *mod) {
    return (entry->stats->priority == mod->priority &&
            (mod->out_port == OFPP_ANY || has_out_port(entry, mod->out_port)) &&
            (mod->out_group == OFPG_ANY || has_out_group(entry, mod->out_group)) &&
            match_std_overlap((struct ofl_match_standard *)entry->stats->match,
                                            (struct ofl_match_standard *)mod->match));
}

/* Replaces the instructions of the given flow entry. */
void
flow_entry_replace_instructions(struct flow_entry *entry,
                                      size_t instructions_num,
                                      struct ofl_instruction_header **instructions) {
    del_group_refs(entry);

    OFL_UTILS_FREE_ARR_FUN3(entry->stats->instructions, entry->stats->instructions_num,
                            ofl_structs_free_instruction, OFL_NO_EXP, NULL/*errbuf*/);

    entry->stats->instructions_num = instructions_num;
    entry->stats->instructions = malloc(sizeof(struct ofl_instruction_header *) *instructions_num);

    size_t i;
    for (i=0; i<instructions_num; i++) {
        entry->stats->instructions[i] = ofl_structs_instruction_clone(instructions[i], OFL_NO_EXP, NULL/*errbuf*/);
    }

    init_group_refs(entry);
}

/* Returns a copy of the entry's flow statistics structure. */
struct ofl_flow_stats * MALLOC_ATTR
flow_entry_stats(struct flow_entry *entry, ev_tstamp now) {
    update(entry, now);

    struct ofl_flow_stats *stats = memcpy(malloc(sizeof(struct ofl_flow_stats)),
                                          entry->stats, sizeof(struct ofl_flow_stats));
    //TODO assumes standard match
    stats->match = memcpy(malloc(sizeof(struct ofl_match_standard)), entry->stats->match,
                          sizeof(struct ofl_match_standard));

    stats->instructions = malloc(sizeof(struct ofl_instruction_header *) * stats->instructions_num);
    size_t i;
    for (i=0; i < entry->stats->instructions_num; i++) {
        stats->instructions[i] = ofl_structs_instruction_clone(entry->stats->instructions[i], OFL_NO_EXP, NULL/*errbuf*/);
    }

    return stats;
}

/* Returns the aggregate stats of the flow. */
struct flow_aggr
flow_entry_stats_aggr(struct flow_entry *entry) {
    return (struct flow_aggr) {
        .packet_count = entry->stats->packet_count,
        .byte_count = entry->stats->byte_count
    };
}

/* Checks whether the flow entry timed out (idle). */
bool
flow_entry_idle_timeout(struct flow_entry *entry, ev_tstamp now) {
    return ((entry->stats->idle_timeout != 0) &&
            (now > entry->last_used + entry->stats->idle_timeout));
}

/* Checks whether the flow entry timed out (hard). */
bool
flow_entry_hard_timeout(struct flow_entry *entry, ev_tstamp now) {
    return (entry->remove_at != 0 && entry->remove_at <= now);
}

/* Returns the instruction with the given type from the set of instructions. */
static struct ofl_instruction_header *
get_instruction(struct ofl_instruction_header **insts, size_t insts_num, uint16_t type) {
    size_t i;

    for (i=0; i < insts_num; i++) {
        if (insts[i]->type == type) {
            return insts[i];
        }
    }

    return NULL;
}


/* Executes the instructions associated with a flow entry */
of_tableid_t
flow_entry_exec(struct flow_entry *flow, struct pl_pkt *pl_pkt, ev_tstamp now) {
    /* NOTE: CLEAR instruction must be executed before WRITE_ACTIONS;
     *       GOTO instruction must be executed last according to spec. */
    struct ofl_instruction_header *inst, *cinst;
    size_t i;
    bool clear_execd = false;
    of_tableid_t next = OF_ALL_TABLE;

    flow->stats->byte_count += pl_pkt->pkt->data_len;
    flow->stats->packet_count++;
    flow->last_used = now;

    for (i=0; i < flow->stats->instructions_num; i++) {
        inst = flow->stats->instructions[i];

        switch (inst->type) {
            case OFPIT_GOTO_TABLE: {
                struct ofl_instruction_goto_table *gi = (struct ofl_instruction_goto_table *)inst;

                next = gi->table_id;
                break;
            }
            case OFPIT_WRITE_METADATA: {
                struct ofl_instruction_write_metadata *wi = (struct ofl_instruction_write_metadata *)inst;

                pl_pkt->metadata = (pl_pkt->metadata & ~wi->metadata_mask) | (wi->metadata & wi->metadata_mask);
                break;
            }
            case OFPIT_WRITE_ACTIONS: {
                struct ofl_instruction_actions *wa = (struct ofl_instruction_actions *)inst;

                /* If no clear action was executed before, check if there is one,
                   and execute it out of order */
                if (!clear_execd) {
                    cinst = get_instruction(flow->stats->instructions, flow->stats->instructions_num, OFPIT_CLEAR_ACTIONS);
                    if (cinst != NULL) {
                        action_set_clear(pl_pkt->act_set);
                        clear_execd = true;
                    }
                    action_set_write_acts(pl_pkt->act_set, wa->actions, wa->actions_num);
                }
                break;
            }
            case OFPIT_APPLY_ACTIONS: {
                struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)inst;

                action_list_exec(flow_table_get_dp_loop(flow->table), pl_pkt, ia->actions, ia->actions_num);
                break;
            }
            case OFPIT_CLEAR_ACTIONS: {
                /* Only execute clear if it has not been executed out of order */
                if (!clear_execd) {
                    action_set_clear(pl_pkt->act_set);
                    clear_execd = true;
                }
                break;
            }
            case OFPIT_EXPERIMENTER: {
                break;
            }
        }
    }

    return next;
}

/* Returns a string representation of the flow entry. */
char * MALLOC_ATTR
flow_entry_to_string(struct flow_entry *entry) {
    return ofl_structs_flow_stats_to_string(entry->stats, OFL_NO_EXP);
}

/* Returns the priority of the flow entry. */
uint16_t
flow_entry_prio(struct flow_entry *flow) {
    return flow->stats->priority;
}

/* Returns the "remove at" timestamp of the flow entry. */
ev_tstamp
flow_entry_remove_at(struct flow_entry *flow) {
    return flow->remove_at;
}
