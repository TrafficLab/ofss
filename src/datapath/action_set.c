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
 * Implements OpenFlow action-set related functions.
 */
#include <assert.h>
#include <stdlib.h>
#include <uthash/utlist.h>
#include "action_set.h"
#include "action.h"
#include "dp.h"
#include "dp_int.h"
#include "pipeline_packet.h"
#include "lib/compiler.h"
#include "lib/list.h"
#include "logger/logger.h"
#include "oflib/ofl.h"
#include "oflib/ofl_actions.h"
#include "oflib/ofl_print.h"
#include "group_table.h"

/* Entry used in the action set for storing the actions.
 * Actions are only pointers to the action structures in the
 * actual write action instructions. */
struct act_set_entry {
    struct list_node           node;
    struct ofl_action_header  *action;
};

/* Stores the set of actions as a list, in their order of precedence. */
struct act_set {
    struct list_node  *actions;
};


/* Returns the priority of the action it should be executed in
 * according to the spec. */
static inline size_t CONST_ATTR
set_order(enum ofp_action_type type) {
    switch (type) {
        case (OFPAT_OUTPUT):         return 90;
        case (OFPAT_SET_VLAN_VID):   return 60;
        case (OFPAT_SET_VLAN_PCP):   return 60;
        case (OFPAT_SET_DL_SRC):     return 60;
        case (OFPAT_SET_DL_DST):     return 60;
        case (OFPAT_SET_NW_SRC):     return 60;
        case (OFPAT_SET_NW_DST):     return 60;
        case (OFPAT_SET_NW_TOS):     return 60;
        case (OFPAT_SET_NW_ECN):     return 60;
        case (OFPAT_SET_TP_SRC):     return 60;
        case (OFPAT_SET_TP_DST):     return 60;
        case (OFPAT_COPY_TTL_OUT):   return 40;
        case (OFPAT_COPY_TTL_IN):    return 10;
        case (OFPAT_SET_MPLS_LABEL): return 60;
        case (OFPAT_SET_MPLS_TC):    return 60;
        case (OFPAT_SET_MPLS_TTL):   return 60;
        case (OFPAT_DEC_MPLS_TTL):   return 50;
        case (OFPAT_PUSH_VLAN):      return 30;
        case (OFPAT_POP_VLAN):       return 20;
        case (OFPAT_PUSH_MPLS):      return 30;
        case (OFPAT_POP_MPLS):       return 20;
        case (OFPAT_SET_QUEUE):      return 70;
        case (OFPAT_GROUP):          return 80;
        case (OFPAT_SET_NW_TTL):     return 60;
        case (OFPAT_DEC_NW_TTL):     return 50;
        case (OFPAT_EXPERIMENTER):   return 75;
        default:                     return 79;
    }
}


/* Creates a new action set (with no actions in it.) */
struct act_set * MALLOC_ATTR
action_set_new() {
    struct act_set *set = malloc(sizeof(struct act_set));
    set->actions = NULL;

    return set;
}

/* Frees up an action set structure. */
void action_set_free(struct act_set *set) {
    action_set_clear(set);
    free(set);
}

/* Creates a clone of the action set.
 * Primarily used when cloning packets in the pipeline. */
struct act_set * MALLOC_ATTR
action_set_clone(struct act_set *set) {
    struct act_set *s = action_set_new();

    struct list_node *node;
    DL_FOREACH(set->actions, node) {
        struct act_set_entry *e = CONTAINER_OF(node, struct act_set_entry, node);
        struct act_set_entry *ne = malloc(sizeof(struct act_set_entry));
        ne->action = e->action;
        DL_APPEND(s->actions, &(ne->node));
    }

    return s;
}


/* Writes a single action to the action set based on the spec:
 * Overwrites existing actions with the same type in the set.
 * The list order is based on the defined precedences. */
static void
action_set_write_act(struct act_set *set, struct ofl_action_header *act) {
    struct list_node *node;
    DL_FOREACH(set->actions, node) {
        struct act_set_entry *e = CONTAINER_OF(node, struct act_set_entry, node);
        if (act->type == e->action->type) {
            /* replace same type of action */
            /* NOTE: action in entry must not be freed, as it is owned by the
             *       write instruction which added the action to the set */
            e->action = act;
            return;
        }
        if (set_order(act->type) < set_order(e->action->type)) {
            struct act_set_entry *ne = malloc(sizeof(struct act_set_entry));
            ne->action = act;
            DL_PREPEND_ELEM(set->actions, &(e->node), &(ne->node));
            return;
        }
    }

    /* add action to the end of set */
    struct act_set_entry *ne = malloc(sizeof(struct act_set_entry));
    ne->action = act;
    DL_APPEND(set->actions, &(ne->node));
}

/* Writes a list of actions to the action set. */
void
action_set_write_acts(struct act_set *set, struct ofl_action_header **actions, size_t actions_num) {
    size_t i;
    for (i=0; i<actions_num; i++) {
        action_set_write_act(set, actions[i]);
    }
}

/* Clears the action set (action set will have zero actions in it). */
void
action_set_clear(struct act_set *set) {
    struct list_node *node, *next;
    DL_FOREACH_SAFE(set->actions, node, next) {
        struct act_set_entry *e = CONTAINER_OF(node, struct act_set_entry, node);
        free(e);
    }
    set->actions = NULL;
}

/* Executes the actions in the action set, according to the spec. */
void
action_set_exec(struct dp_loop *dp_loop, struct act_set *set, struct pl_pkt *pl_pkt) {
    struct list_node *node, *next;

    logger_log(pl_pkt->logger, LOG_DEBUG, "Executing action set.");

    DL_FOREACH_SAFE(set->actions, node, next) {
        struct act_set_entry *e = CONTAINER_OF(node, struct act_set_entry, node);

        struct act_res res = action_exec(pl_pkt, e->action);
        /* NOTE: action in entry must not be freed, as it is owned by the
         *       write instruction which added the action to the set */
        DL_DELETE(set->actions, node);
        free(e);

        /* According to the spec. if there was a group action, the output
         * port action should be ignored.
         * NOTE: Currently only port action can be after a group action. */
        switch (res.type) {
            case DP_ACT_GROUP: {
                action_set_clear(set);
                group_table_exec(dp_loop->groups, pl_pkt, res.group_id);
                return;
            }
            case DP_ACT_PORT: {
                dp_pl_pkt_to_port(dp_loop, res.port.port_id, res.port.max_len, pl_pkt);
                // act_set_should be clear now as output is the last action in order
                assert(set->actions == NULL);
                return;
            }
            default: {
                break;
            }
        }
    }
    // set should be empty by now
    assert(set->actions == NULL);
}


/* Converts the action set to string format for display. */
char * MALLOC_ATTR
action_set_to_string(struct act_set *set) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    action_set_print(stream, set);

    fclose(stream);
    return str;
}

/* Writes a string representation of the action set to the stream. */
void
action_set_print(FILE *stream, struct act_set *set) {
    fprintf(stream, "[");

    bool first = true;
    struct list_node *node;
    DL_FOREACH(set->actions, node) {
        struct act_set_entry *e = CONTAINER_OF(node, struct act_set_entry, node);
        if (first) { first = false; } else { fprintf(stream, ", "); }
        ofl_action_print(stream, e->action, OFL_NO_EXP);
    }

    fprintf(stream, "]");
}

