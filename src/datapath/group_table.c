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
 * Represents the group table of a DP.
 */

#include <stddef.h>
#include <uthash/uthash.h>
#include "control/ctrl.h"
#include "logger/logger.h"
#include "logger/logger_mgr.h"
#include "lib/compiler.h"
#include "lib/logger_names.h"
#include "group_table.h"
#include "group_entry.h"
#include "dp.h"
#include "action.h"
#include "action_list.h"
#include "dp_int.h"
#include "pipeline_packet.h"
#include "dp_ctrl.h"

#define MAX_GROUPS   4096
#define MAX_BUCKETS   16384

#define VISITED_INIT_SIZE  16

struct dp_loop;

/* structure for storing group entries in containers. */
struct group {
    of_groupid_t       id;
    struct group_entry  *entry;
    UT_hash_handle     hh;
};


/* helper structure for loop checking. */
struct loop_arr {
    of_groupid_t (*arr)[];
    size_t       size;
    size_t       elems;
    size_t       max_elems;
};

struct group_table {
    struct dp_loop   *dp_loop;
    struct logger    *logger;
    size_t            groups_num;
    struct group     *groups;
    size_t            buckets_num;

    // preallocated arrays for loop_free calculations
    struct loop_arr  *visited;
    struct loop_arr  *to_be_visited;
};

static struct loop_arr *
loop_arr_new(size_t init_size);

static bool
is_loop_free(struct group_table *table, struct ofl_msg_group_mod *mod);

/* Creates a new group table. */
struct group_table * MALLOC_ATTR
group_table_new(struct dp_loop *dp_loop) {
    struct group_table *group_tab = malloc(sizeof(struct group_table));
    group_tab->dp_loop = dp_loop;
    group_tab->logger = logger_mgr_get(LOGGER_NAME_DP_GROUPTABLE, dp_loop_get_uid(dp_loop));

    group_tab->groups_num = 0;
    group_tab->groups = NULL;
    group_tab->buckets_num = 0;

    group_tab->visited = loop_arr_new(VISITED_INIT_SIZE);
    group_tab->to_be_visited = loop_arr_new(VISITED_INIT_SIZE);
    group_tab->visited->elems = 0;
    group_tab->visited->max_elems = 0;


    return group_tab;
}

/* Requests the group table to execute the group entry on the packet. */
void
group_table_exec(struct group_table *table, struct pl_pkt *pl_pkt, of_groupid_t group_id) {
    struct group *group;
    HASH_FIND(hh, table->groups, &group_id, sizeof(of_groupid_t), group);

    if (group == NULL) {
        logger_log(table->logger, LOG_WARN, "Trying to execute non-existing group (%u).", group_id);
        return;
    }

    group_entry_exec(group->entry, pl_pkt);
}

/* Handles group mod messages with ADD command. */
static ofl_err
mod_add(struct group_table *table, struct dp_msg *msg) {
    struct ofl_msg_group_mod *mod = (struct ofl_msg_group_mod *)(msg->msg);

    struct group *group;
    HASH_FIND(hh, table->groups, &(mod->group_id), sizeof(of_groupid_t), group);

    if (group != NULL) {
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_GROUP_EXISTS);
    }

    if (table->groups_num == MAX_GROUPS) {
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_OUT_OF_GROUPS);
    }

    if (table->buckets_num + mod->buckets_num > MAX_BUCKETS) {
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_OUT_OF_BUCKETS);
    }

    group = malloc(sizeof(struct group));
    group->entry = group_entry_new(table->dp_loop, mod);
    group->id = mod->group_id;
    HASH_ADD(hh, table->groups, id, sizeof(of_groupid_t), group);

    table->groups_num++;
    table->buckets_num += mod->buckets_num;

    ofl_msg_free_group_mod(mod, false, OFL_NO_EXP, NULL/*errbuf*/);
    free(msg->ofp_msg);

    return 0;
}

/* Handles group_mod messages with MODIFY command. */
static ofl_err
mod_modify(struct group_table *table, struct dp_msg *msg) {
    struct ofl_msg_group_mod *mod = (struct ofl_msg_group_mod *)(msg->msg);

    struct group *group;
    HASH_FIND(hh, table->groups, &(mod->group_id), sizeof(of_groupid_t), group);
    if (group == NULL) {
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_UNKNOWN_GROUP);
    }

    size_t buckets_diff = mod->buckets_num - group_entry_buckets_num(group->entry);
    if (table->buckets_num - buckets_diff > MAX_BUCKETS) {
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_OUT_OF_BUCKETS);
    }

    if (!is_loop_free(table, mod)) {
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_LOOP);
    }

    group_entry_replace_buckets(group->entry, mod->buckets_num, mod->buckets);
    table->buckets_num += buckets_diff;

    ofl_msg_free_group_mod(mod, false, OFL_NO_EXP, NULL/*errbuf*/);
    free(msg->ofp_msg);
    return 0;
}

/* Handles group mod messages with DELETE command. */
static ofl_err
mod_delete(struct group_table *table, struct dp_msg *msg) {
    struct ofl_msg_group_mod *mod = (struct ofl_msg_group_mod *)(msg->msg);

    if (mod->group_id == OFPG_ALL) {
        struct group *group, *next;
        HASH_ITER(hh, table->groups, group, next) {
            group_entry_free(group->entry);
            HASH_DEL(table->groups, group);
            free(group);
        }

        table->groups_num = 0;
        table->buckets_num = 0;
    } else {
        struct group *group;
        HASH_FIND(hh, table->groups, &(mod->group_id), sizeof(of_groupid_t), group);

        /* NOTE: In 1.1 no error should be sent, if delete is for a non-existing group. */
        if (group != NULL) {
            /* NOTE: The spec. does not define what happens when groups refer to groups
                     which are being deleted. For now deleting such a group is not allowed. */
            struct group *g, *n;
            HASH_ITER(hh, table->groups, g, n) {
                if (group_entry_has_out_group(g->entry, group->id)) {
                    return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_CHAINING_UNSUPPORTED);
                }
            }

            table->groups_num--;
            table->buckets_num -= group_entry_buckets_num(group->entry);

            group_entry_free(group->entry);
            HASH_DEL(table->groups, group);
            free(group);
        }
    }

    ofl_msg_free_group_mod(mod, true, OFL_NO_EXP, NULL/*errbuf*/);
    free(msg->ofp_msg);
    return 0;
}

/* Dispatches group mod messages to the handlers. */
ofl_err
group_table_group_mod(struct group_table *table, struct dp_msg *msg) {
    struct ofl_msg_group_mod *mod = (struct ofl_msg_group_mod *)(msg->msg);

    size_t i;
    for (i=0; i< mod->buckets_num; i++) {
        ofl_err error = action_list_validate(table->dp_loop, mod->buckets[i]->actions, mod->buckets[i]->actions_num);
        if (error) {
            return error;
        }
    }

    switch (mod->command) {
        case (OFPGC_ADD): {
            return mod_add(table, msg);
        }
        case (OFPGC_MODIFY): {
            return mod_modify(table, msg);
        }
        case (OFPGC_DELETE): {
            return mod_delete(table, msg);
        }
        default: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_SUBTYPE);
        }
    }
}

/* Handles group desc stats requests. */
ofl_err
group_table_stats_group_desc(struct group_table *table, struct dp_msg *msg) {
    struct ofl_msg_stats_reply_group_desc *reply = malloc(sizeof(struct ofl_msg_stats_reply_group_desc));

    reply->header.header.type = OFPT_STATS_REPLY;
    reply->header.type = OFPST_GROUP_DESC;
    reply->header.flags = 0x0000;

    reply->stats_num = HASH_COUNT(table->groups);
    reply->stats = malloc(sizeof(struct ofl_group_desc_stats) * reply->stats_num);

    size_t i = 0;
    struct group *group, *next;
    HASH_ITER(hh, table->groups, group, next) {
        reply->stats[i] = group_entry_desc_stats(group->entry);
        i++;
    }

    dp_ctrl_send_msg(table->dp_loop, msg->conn_id, msg->xid, (struct ofl_msg_header *)reply);
    ofl_msg_free(msg->msg, OFL_NO_EXP, NULL/*errbuf*/);
    free(msg->ofp_msg);
    return 0;
}

/* Handles group stats requests. */
ofl_err
group_table_stats_group(struct group_table *table, struct dp_msg *msg) {
    struct ofl_msg_stats_request_group *req = (struct ofl_msg_stats_request_group *)(msg->msg);

    struct group_entry *entry = NULL;

    if (req->group_id != OFPG_ALL) {
        struct group *group;
        HASH_FIND(hh, table->groups, &(req->group_id), sizeof(of_groupid_t), group);
        if (group == NULL) {
            return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_UNKNOWN_GROUP);
        }
        entry = group->entry;
    }

    struct ofl_msg_stats_reply_group *reply = malloc(sizeof(struct ofl_msg_stats_reply_group));
    reply->header.header.type = OFPT_STATS_REPLY;
    reply->header.type = OFPST_GROUP;
    reply->header.flags = 0x0000;

    if (entry != NULL) {
        // request for one
        reply->stats_num = 1;
        reply->stats = malloc(sizeof(struct ofl_group_stats));
        reply->stats[0] = group_entry_stats(entry);
    } else {
        // request for all
        reply->stats_num = HASH_COUNT(table->groups);
        reply->stats = malloc(sizeof(struct ofl_group_stats) * reply->stats_num);

        size_t i = 0;
        struct group *group, *next;
        HASH_ITER(hh, table->groups, group, next) {
            reply->stats[i] = group_entry_stats(group->entry);
            i++;
        }
    }

    dp_ctrl_send_msg(table->dp_loop, msg->conn_id, msg->xid, (struct ofl_msg_header *)reply);
    ofl_msg_free(msg->msg, OFL_NO_EXP, NULL/*errbuf*/);
    free(msg->ofp_msg);
    return 0;
}

/* Tells whether the entry exists in the table. */
bool
group_table_has(struct group_table *group_table, of_groupid_t group_id) {
    struct group *group;
    HASH_FIND(hh, group_table->groups, &group_id, sizeof(of_groupid_t), group);

    return (group != NULL);
}

/* Creates a new loop checking array. */
static MALLOC_ATTR struct loop_arr *
loop_arr_new(size_t init_size) {
    struct loop_arr *loop_arr = malloc(sizeof(struct loop_arr));
    loop_arr->arr = malloc(sizeof(of_groupid_t) * init_size);
    loop_arr->size = init_size;
    loop_arr->elems = 0;
    loop_arr->max_elems = 0;

    return loop_arr;
}

/* Clears a loop checking array. */
static void
loop_arr_clear(struct loop_arr *loop_arr) {
    loop_arr->elems = 0;
    loop_arr->max_elems = 0;
}

/* Tells whether group is in the array. */
static bool
loop_arr_is_in(struct loop_arr *loop_arr, of_groupid_t id) {
    size_t i;
    for (i=0; i<loop_arr->max_elems; i++) {
        if ((*(loop_arr->arr))[i] == id) {
            return true;
        }
    }
    return false;
}

/* Adds group to the loop array. */
static void
loop_arr_add(struct loop_arr *loop_arr, of_groupid_t id) {
    if (loop_arr->max_elems == loop_arr->size) {
        loop_arr->size *= 2;
        loop_arr->arr = realloc(loop_arr->arr, sizeof(of_groupid_t) * loop_arr->size);
    }

    (*(loop_arr->arr))[loop_arr->max_elems] = id;
    loop_arr->elems++;
    loop_arr->max_elems++;
}

/* Pops the next group from the array. */
static of_groupid_t
loop_arr_pop(struct loop_arr *loop_arr) {
    size_t i;
    for (i=0; i<loop_arr->max_elems; i++) {
        if ((*(loop_arr->arr))[i] != OFPG_ANY) {
            of_groupid_t ret = (*(loop_arr->arr))[i];
            (*(loop_arr->arr))[i] = OFPG_ANY;
            loop_arr->elems--;
            return ret;
        }
    }
    return OFPG_ALL;
}

/* Visits the given group during loop avoidance check. */
static void
visit(struct ofl_bucket **buckets, size_t buckets_num,
      struct loop_arr *visited, struct loop_arr *to_be_visited) {
    size_t ib;
    for (ib=0; ib<buckets_num; ib++) {
        size_t ia;
        for (ia=0; ia<buckets[ib]->actions_num; ia++) {
            if (buckets[ib]->actions[ia]->type == OFPAT_GROUP) {
                struct ofl_action_group *act = (struct ofl_action_group *) buckets[ib]->actions[ia];

                if (!loop_arr_is_in(visited, act->group_id) &&
                    !loop_arr_is_in(to_be_visited, act->group_id)) {
                    loop_arr_add(to_be_visited, act->group_id);
                }
            }
        }
    }
}

/* Checks whether modifying the given group causes a loop or not. */
static bool
is_loop_free(struct group_table *table, struct ofl_msg_group_mod *mod) {
/* Note: called when a modify is called on group. Table is the actual
 *       table, and mod is the modified entry. Returns true if the
 *       table would remain loop free after the modification.
 *       It is assumed that table is loop free without the modification.
 */

    loop_arr_clear(table->visited);
    loop_arr_clear(table->to_be_visited);

    visit(mod->buckets, mod->buckets_num, table->visited, table->to_be_visited);

    while(table->to_be_visited->elems > 0) {
        // if modified entry is to be visited, there is a loop
        if (loop_arr_is_in(table->to_be_visited, mod->group_id)) {
            break;
        }

        // retrieve first element from to be visited
        of_groupid_t vid = loop_arr_pop(table->to_be_visited);

        struct group *group;
        HASH_FIND(hh, table->groups, &vid, sizeof(of_groupid_t), group);

        if (group != NULL) {
            visit(group_entry_buckets(group->entry), group_entry_buckets_num(group->entry), table->visited, table->to_be_visited);
        } else {
            logger_log(table->logger, LOG_ERR, "is_loop_free cannot find group (%u).", vid);
        }

        loop_arr_add(table->visited, vid);
    }

    return (table->to_be_visited->elems == 0);
}

/* Adds a flow reference to the given group. */
void
group_table_add_flow_ref(struct group_table *group_table, of_groupid_t group_id, uint32_t flow_ref) {
    struct group *group;
    HASH_FIND(hh, group_table->groups, &(group_id), sizeof(of_groupid_t), group);
    if (group != NULL) {
        group_entry_add_flow_ref(group->entry, flow_ref);
    } else {
        //TODO error
    }
}

/* Removes a flow reference from the given group. */
void
group_table_del_flow_ref(struct group_table *group_table, of_groupid_t group_id, uint32_t flow_ref) {
    struct group *group;
    HASH_FIND(hh, group_table->groups, &(group_id), sizeof(of_groupid_t), group);
    if (group != NULL) {
        group_entry_del_flow_ref(group->entry, flow_ref);
    } else {
        //TODO error
    }
}

/* Returns the logger of the group table (used by entries). */
struct logger *
group_table_get_logger(struct group_table *group_table) {
    return group_table->logger;
}
