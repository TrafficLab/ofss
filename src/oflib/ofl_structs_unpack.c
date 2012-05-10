/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <openflow/openflow.h>
#include "ofl.h"
#include "ofl_print.h"
#include "ofl_actions.h"
#include "ofl_structs.h"
#include "ofl_utils.h"
#include "ofl_packets.h"

ofl_err
ofl_structs_instructions_unpack(struct ofp_instruction *src, size_t *len, struct ofl_instruction_header **dst, struct ofl_exp *exp, char *errbuf) {
    size_t ilen;
    struct ofl_instruction_header *inst = NULL;

    if (*len < sizeof(struct ofp_instruction)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received instruction is too short (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    if (*len < ntohs(src->len)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received instruction has invalid length (set to %u, but only %zu received).", ntohs(src->len), *len);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }
    ilen = ntohs(src->len);

    switch (ntohs(src->type)) {
        case OFPIT_GOTO_TABLE: {
            struct ofp_instruction_goto_table *si;
            struct ofl_instruction_goto_table *di;

            if (ilen < sizeof(struct ofp_instruction_goto_table)) {
                if (errbuf != NULL) {
                    snprintf(errbuf, OFL_ERRBUF_SIZE, "Received GOTO_TABLE instruction has invalid length (%zu).", *len);
                }
                return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
            }

            si = (struct ofp_instruction_goto_table *)src;

            if (si->table_id == 0xff) {
                if (errbuf != NULL) {
                    char *ts = ofl_table_to_string(si->table_id);
                    snprintf(errbuf, OFL_ERRBUF_SIZE, "Received GOTO_TABLE instruction has invalid table_id (%s).", ts);
                    free(ts);
                }
                return ofl_error(OFPET_BAD_INSTRUCTION, OFPBIC_BAD_TABLE_ID);
            }

            di = (struct ofl_instruction_goto_table *)malloc(sizeof(struct ofl_instruction_goto_table));

            di->table_id = si->table_id;

            inst = (struct ofl_instruction_header *)di;
            ilen -= sizeof(struct ofp_instruction_goto_table);
            break;
        }

        case OFPIT_WRITE_METADATA: {
            struct ofp_instruction_write_metadata *si;
            struct ofl_instruction_write_metadata *di;

            if (ilen < sizeof(struct ofp_instruction_write_metadata)) {
                if (errbuf != NULL) {
                    snprintf(errbuf, OFL_ERRBUF_SIZE, "Received WRITE_METADATA instruction has invalid length (%zu).", *len);
                }
                return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
            }

            si = (struct ofp_instruction_write_metadata *)src;
            di = (struct ofl_instruction_write_metadata *)malloc(sizeof(struct ofl_instruction_write_metadata));

            di->metadata =      si->metadata;
            di->metadata_mask = si->metadata_mask;

            inst = (struct ofl_instruction_header *)di;
            ilen -= sizeof(struct ofp_instruction_write_metadata);
            break;
        }
        case OFPIT_WRITE_ACTIONS:
        case OFPIT_APPLY_ACTIONS: {
            struct ofp_instruction_actions *si;
            struct ofl_instruction_actions *di;
            struct ofp_action_header *act;
            ofl_err error;
            size_t i;

            if (ilen < sizeof(struct ofp_instruction_actions)) {
                if (errbuf != NULL) {
                    snprintf(errbuf, OFL_ERRBUF_SIZE, "Received *_ACTIONS instruction has invalid length (%zu).", *len);
                }
                return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
            }
            ilen -= sizeof(struct ofp_instruction_actions);

            si = (struct ofp_instruction_actions *)src;
            di = (struct ofl_instruction_actions *)malloc(sizeof(struct ofl_instruction_actions));

            error = ofl_utils_count_ofp_actions((uint8_t *)si->actions, ilen, &di->actions_num, errbuf);
            if (error) {
                free(di);
                return error;
            }
            di->actions = (struct ofl_action_header **)malloc(di->actions_num * sizeof(struct ofl_action_header *));

            act = si->actions;
            for (i = 0; i < di->actions_num; i++) {
                error = ofl_actions_unpack(act, &ilen, &(di->actions[i]), exp, errbuf);
                if (error) {
                    *len = *len - ntohs(src->len) + ilen;
                    OFL_UTILS_FREE_ARR_FUN3(di->actions, i,
                                            ofl_actions_free, exp, errbuf);
                    //TODO error
                    free(di);
                    return error;
                }
                act = (struct ofp_action_header *)((uint8_t *)act + ntohs(act->len));
            }

            inst = (struct ofl_instruction_header *)di;
            break;
        }
        case OFPIT_CLEAR_ACTIONS: {
            if (ilen < sizeof(struct ofp_instruction_actions)) {
                if (errbuf != NULL) {
                    snprintf(errbuf, OFL_ERRBUF_SIZE, "Received CLEAR_ACTIONS instruction has invalid length (%zu).", *len);
                }
                return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
            }

            inst = (struct ofl_instruction_header *)malloc(sizeof(struct ofl_instruction_header));
            inst->type = (enum ofp_instruction_type)ntohs(src->type);

            ilen -= sizeof(struct ofp_instruction_actions);
            break;
        }

        case OFPIT_EXPERIMENTER: {
            ofl_err error;

            if (exp == NULL || exp->inst == NULL || exp->inst->unpack == NULL) {
                if (errbuf != NULL) {
                    snprintf(errbuf, OFL_ERRBUF_SIZE, "Received EXPERIMENTER instruction, but no callback was given.");
                }
                return ofl_error(OFPET_BAD_INSTRUCTION, OFPBIC_UNSUP_EXP_INST);
            }
            error = exp->inst->unpack(src, &ilen, &inst);
            if (error) {
                return error;
            }
            break;
        }
    }

    // must set type before check, so free works correctly
    inst->type = (enum ofp_instruction_type)ntohs(src->type);

    if (ilen != 0) {
        *len = *len - ntohs(src->len) + ilen;
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "The received instruction contained extra bytes (%zu).", ilen);
        }
        ofl_structs_free_instruction(inst, exp, errbuf);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    *len -= ntohs(src->len);
    (*dst) = inst;

    return 0;
}


ofl_err
ofl_structs_bucket_unpack(struct ofp_bucket *src, size_t *len, uint8_t gtype, struct ofl_bucket **dst, struct ofl_exp *exp, char *errbuf) {
    struct ofl_bucket *b;
    struct ofp_action_header *act;
    size_t blen;
    ofl_err error;
    size_t i;

    if (*len < sizeof(struct ofp_bucket)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received bucket is too short (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    if (*len < ntohs(src->len)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received bucket has invalid length (set to %u, but only %zu received).", ntohs(src->len), *len);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    blen = ntohs(src->len) - sizeof(struct ofp_bucket);

    if (gtype == OFPGT_SELECT && ntohs(src->weight) == 0) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received bucket has no weight for SELECT group.");
        }
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_INVALID_GROUP);
    }

    if (gtype != OFPGT_SELECT && ntohs(src->weight) > 0) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received bucket has weight for non-SELECT group.");
        }
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_INVALID_GROUP);
    }

    b = (struct ofl_bucket *)malloc(sizeof(struct ofl_bucket));

    b->weight =      ntohs(src->weight);
    b->watch_port =  ntohl(src->watch_port);
    b->watch_group = ntohl(src->watch_group);

    error = ofl_utils_count_ofp_actions((uint8_t *)src->actions, blen, &b->actions_num, errbuf);
    if (error) {
        free(b);
        return error;
    }
    b->actions = (struct ofl_action_header **)malloc(b->actions_num * sizeof(struct ofl_action_header *));

    act = src->actions;
    for (i = 0; i < b->actions_num; i++) {
        error = ofl_actions_unpack(act, &blen, &(b->actions[i]), exp, errbuf);
        if (error) {
            *len = *len - ntohs(src->len) + blen;
            OFL_UTILS_FREE_ARR_FUN3(b->actions, i,
                                    ofl_actions_free, exp, errbuf);
            //TODO error
            free(b);
            return error;
        }
        act = (struct ofp_action_header *)((uint8_t *)act + ntohs(act->len));
    }

    if (blen >= 8) {
        *len = *len - ntohs(src->len) + blen;
        ofl_structs_free_bucket(b, exp, errbuf);
        //TODO error
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received bucket has more than 64 bit padding (%zu).", blen);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= ntohs(src->len);

    *dst = b;
    return 0;
}


ofl_err
ofl_structs_flow_stats_unpack(struct ofp_flow_stats *src, size_t *len, struct ofl_flow_stats **dst, struct ofl_exp *exp, char *errbuf) {
    struct ofl_flow_stats *s;
    struct ofp_instruction *inst;
    ofl_err error;
    size_t slen;
    size_t i;

    if (*len < (sizeof(struct ofp_flow_stats) - sizeof(struct ofp_match))) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received flow stats has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }

    if (*len < ntohs(src->length)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received flow stats reply has invalid length (set to %u, but only %zu received).", ntohs(src->length), *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    if (src->table_id == 0xff) {
        if (errbuf != NULL) {
            char *ts = ofl_table_to_string(src->table_id);
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received flow stats has invalid table_id (%s).", ts);
            free(ts);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }

    slen = ntohs(src->length) - (sizeof(struct ofp_flow_stats) - sizeof(struct ofp_match));

    s = (struct ofl_flow_stats *)malloc(sizeof(struct ofl_flow_stats));

    s->table_id =             src->table_id;
    s->duration_sec =  ntohl( src->duration_sec);
    s->duration_nsec = ntohl( src->duration_nsec);
    s->priority =      ntohs( src->priority);
    s->idle_timeout =  ntohs( src->idle_timeout);
    s->hard_timeout =  ntohs( src->hard_timeout);
    s->cookie =        ntoh64(src->cookie);
    s->packet_count =  ntoh64(src->packet_count);
    s->byte_count =    ntoh64(src->byte_count);

    error = ofl_structs_match_unpack(&(src->match), &slen, &(s->match), exp, errbuf);
    if (error) {
        free(s);
        return error;
    }

    error = ofl_utils_count_ofp_instructions(src->instructions, slen, &s->instructions_num, errbuf);
    if (error) {
        ofl_structs_free_match(s->match, exp, NULL);
        free(s);
        return error;
    }
    s->instructions = (struct ofl_instruction_header **)malloc(s->instructions_num * sizeof(struct ofl_instruction_header *));

    inst = src->instructions;
    for (i = 0; i < s->instructions_num; i++) {
        error = ofl_structs_instructions_unpack(inst, &slen, &(s->instructions[i]), exp, errbuf);
        if (error) {
            OFL_UTILS_FREE_ARR_FUN3(s->instructions, i,
                                    ofl_structs_free_instruction, exp, errbuf);
            free(s);
            return error;
        }
        inst = (struct ofp_instruction *)((uint8_t *)inst + ntohs(inst->len));
    }

    if (slen != 0) {
        *len = *len - ntohs(src->length) + slen;
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "The received flow stats contained extra bytes (%zu).", slen);
        }
        ofl_structs_free_flow_stats(s, exp, errbuf);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    *len -= ntohs(src->length);
    *dst = s;
    return 0;
}


ofl_err
ofl_structs_group_stats_unpack(struct ofp_group_stats *src, size_t *len, struct ofl_group_stats **dst, char *errbuf) {
    struct ofl_group_stats *s;
    struct ofp_bucket_counter *c;
    ofl_err error;
    size_t slen;
    size_t i;

    if (*len < sizeof(struct ofp_group_stats)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received group desc stats reply is too short (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }

    if (*len < ntohs(src->length)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received group stats reply has invalid length (set to %u, but only %zu received).", ntohs(src->length), *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    if (ntohl(src->group_id) > OFPG_MAX) {
        if (errbuf != NULL) {
            char *gs = ofl_group_to_string(ntohl(src->group_id));
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received group stats has invalid group_id (%s).", gs);
            free(gs);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }
    slen = ntohs(src->length) - sizeof(struct ofp_group_stats);

    s = (struct ofl_group_stats *)malloc(sizeof(struct ofl_group_stats));
    s->group_id = ntohl(src->group_id);
    s->ref_count = ntohl(src->ref_count);
    s->packet_count = ntoh64(src->packet_count);
    s->byte_count = ntoh64(src->byte_count);

    error = ofl_utils_count_ofp_bucket_counters(src->bucket_stats, slen, &s->counters_num);
    if (error) {
        free(s);
        return error;
    }
    s->counters = (struct ofl_bucket_counter **)malloc(s->counters_num * sizeof(struct ofl_bucket_counter *));

    c = src->bucket_stats;
    for (i = 0; i < s->counters_num; i++) {
        error = ofl_structs_bucket_counter_unpack(c, &slen, &(s->counters[i]), errbuf);
        if (error) {
            OFL_UTILS_FREE_ARR(s->counters, i);
            free(s);
            return error;
        }
        c = (struct ofp_bucket_counter *)((uint8_t *)c + sizeof(struct ofp_bucket_counter));
    }

    if (slen != 0) {
        *len = *len - ntohs(src->length) + slen;
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "The received group stats contained extra bytes (%zu).", slen);
        }
        ofl_structs_free_group_stats(s);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    *len -= ntohs(src->length);
    *dst = s;
    return 0;
}


ofl_err
ofl_structs_queue_prop_unpack(struct ofp_queue_prop_header *src, size_t *len, struct ofl_queue_prop_header **dst, char *errbuf) {

    if (*len < sizeof(struct ofp_action_header)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received queue property is too short (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    if (*len < ntohs(src->len)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received queue property has invalid length (set to %u, but only %zu received).", ntohs(src->len), *len);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    switch (ntohs(src->property)) {
        case OFPQT_MIN_RATE: {
            struct ofp_queue_prop_min_rate *sp = (struct ofp_queue_prop_min_rate *)src;
            struct ofl_queue_prop_min_rate *dp = (struct ofl_queue_prop_min_rate *)malloc(sizeof(struct ofl_queue_prop_min_rate));

            if (*len < sizeof(struct ofp_queue_prop_min_rate)) {
                if (errbuf != NULL) {
                    snprintf(errbuf, OFL_ERRBUF_SIZE, "Received MIN_RATE queue property has invalid length (%zu).", *len);
                }
                return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
            }
            *len -= sizeof(struct ofp_queue_prop_min_rate);

            dp->rate = ntohs(sp->rate);

            *dst = (struct ofl_queue_prop_header *)dp;
            break;
        }
        default: {
            if (errbuf != NULL) {
                snprintf(errbuf, OFL_ERRBUF_SIZE, "Received unknown queue prop type.");
            }
            return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
        }
    }

    (*dst)->type = (enum ofp_queue_properties)ntohs(src->property);
    return 0;
}


ofl_err
ofl_structs_packet_queue_unpack(struct ofp_packet_queue *src, size_t *len, struct ofl_packet_queue **dst, char *errbuf) {
    struct ofl_packet_queue *q;
    struct ofp_queue_prop_header *prop;
    ofl_err error;
    size_t i;

    if (*len < ntohs(src->len)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received packet queue has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_packet_queue);

    q = (struct ofl_packet_queue *)malloc(sizeof(struct ofl_packet_queue));
    q->queue_id = ntohl(src->queue_id);

    error = ofl_utils_count_ofp_queue_props((uint8_t *)src->properties, *len, &q->properties_num, errbuf);
    if (error) {
        free(q);
        return error;
    }
    q->properties = (struct ofl_queue_prop_header **)malloc(q->properties_num * sizeof(struct ofl_queue_prop_header *));

    prop = src->properties;
    for (i = 0; i < q->properties_num; i++) {
        ofl_structs_queue_prop_unpack(prop, len, &(q->properties[i]), errbuf);
        //TODO error
        prop = (struct ofp_queue_prop_header *)((uint8_t *)prop + ntohs(prop->len));
    }

    *dst = q;
    return 0;
}


ofl_err
ofl_structs_port_unpack(struct ofp_port *src, size_t *len, struct ofl_port **dst, char *errbuf) {
    struct ofl_port *p;

    if (*len < sizeof(struct ofp_port)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received port has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }

    if (ntohl(src->port_no) == 0 ||
        (ntohl(src->port_no) > OFPP_MAX && ntohl(src->port_no) != OFPP_LOCAL)) {
        if (errbuf != NULL) {
            char *ps = ofl_port_to_string(ntohl(src->port_no));
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received port has invalid port_id (%s).", ps);
            free(ps);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_port);

    p = (struct ofl_port *)malloc(sizeof(struct ofl_port));

    p->port_no = ntohl(src->port_no);
    memcpy(p->hw_addr, src->hw_addr, ETH_ADDR_LEN);
    p->name = strcpy((char *)malloc(strlen(src->name) + 1), src->name);
    p->config = ntohl(src->config);
    p->state = ntohl(src->state);
    p->curr = ntohl(src->curr);
    p->advertised = ntohl(src->advertised);
    p->supported = ntohl(src->supported);
    p->peer = ntohl(src->peer);
    p->curr_speed = ntohl(src->curr_speed);
    p->max_speed = ntohl(src->max_speed);

    *dst = p;
    return 0;
}



ofl_err
ofl_structs_table_stats_unpack(struct ofp_table_stats *src, size_t *len, struct ofl_table_stats **dst, char *errbuf) {
    struct ofl_table_stats *p;

    if (*len < sizeof(struct ofp_table_stats)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received table stats has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }

    if (src->table_id == 0xff) {
        if (errbuf != NULL) {
            char *ts = ofl_table_to_string(src->table_id);
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received table stats has invalid table_id (%s).", ts);
            free(ts);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_table_stats);

    p = (struct ofl_table_stats *)malloc(sizeof(struct ofl_table_stats));
    p->table_id =      src->table_id;
    p->name =          strcpy((char *)malloc(strlen(src->name) + 1), src->name);
    p->wildcards =     ntohl(src->wildcards);
    p->match =         ntohl(src->match);
    p->instructions =  ntohl(src->instructions);
    p->write_actions = ntohl(src->write_actions);
    p->apply_actions = ntohl(src->apply_actions);
    p->config =        ntohl(src->config);
    p->max_entries =   ntohl(src->max_entries);
    p->active_count =  ntohl(src->active_count);
    p->lookup_count =  ntoh64(src->lookup_count);
    p->matched_count = ntoh64(src->matched_count);

    *dst = p;
    return 0;
}

ofl_err
ofl_structs_port_stats_unpack(struct ofp_port_stats *src, size_t *len, struct ofl_port_stats **dst, char *errbuf) {
    struct ofl_port_stats *p;

    if (*len < sizeof(struct ofp_port_stats)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received port stats has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }
    if (ntohl(src->port_no) == 0 ||
        (ntohl(src->port_no) > OFPP_MAX && ntohl(src->port_no) != OFPP_LOCAL)) {
        if (errbuf != NULL) {
            char *ps = ofl_port_to_string(ntohl(src->port_no));
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received port stats has invalid port_id (%s).", ps);
            free(ps);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_port_stats);

    p = (struct ofl_port_stats *)malloc(sizeof(struct ofl_port_stats));

    p->port_no      = ntohl(src->port_no);
    p->rx_packets   = ntoh64(src->rx_packets);
    p->tx_packets   = ntoh64(src->tx_packets);
    p->rx_bytes     = ntoh64(src->rx_bytes);
    p->tx_bytes     = ntoh64(src->tx_bytes);
    p->rx_dropped   = ntoh64(src->rx_dropped);
    p->tx_dropped   = ntoh64(src->tx_dropped);
    p->rx_errors    = ntoh64(src->rx_errors);
    p->tx_errors    = ntoh64(src->tx_errors);
    p->rx_frame_err = ntoh64(src->rx_frame_err);
    p->rx_over_err  = ntoh64(src->rx_over_err);
    p->rx_crc_err   = ntoh64(src->rx_crc_err);
    p->collisions   = ntoh64(src->collisions);

    *dst = p;
    return 0;
}

ofl_err
ofl_structs_queue_stats_unpack(struct ofp_queue_stats *src, size_t *len, struct ofl_queue_stats **dst, char *errbuf) {
    struct ofl_queue_stats *p;

    if (*len < sizeof(struct ofp_queue_stats)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received queue stats has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    if (ntohl(src->port_no) == 0 || ntohl(src->port_no) > OFPP_MAX) {
        if (errbuf != NULL) {
            char *ps = ofl_port_to_string(ntohl(src->port_no));
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received queue stats has invalid port_id (%s).", ps);
            free(ps);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_queue_stats);

    p = (struct ofl_queue_stats *)malloc(sizeof(struct ofl_queue_stats));

    p->port_no =    ntohl(src->port_no);
    p->queue_id =   ntohl(src->queue_id);
    p->tx_bytes =   ntoh64(src->tx_bytes);
    p->tx_packets = ntoh64(src->tx_packets);
    p->tx_errors =  ntoh64(src->tx_errors);

    *dst = p;
    return 0;
}

ofl_err
ofl_structs_group_desc_stats_unpack(struct ofp_group_desc_stats *src, size_t *len, struct ofl_group_desc_stats **dst, struct ofl_exp *exp, char *errbuf) {
    struct ofl_group_desc_stats *dm;
    struct ofp_bucket *bucket;
    ofl_err error;
    size_t dlen;
    size_t i;

    if (*len < sizeof(struct ofp_group_desc_stats)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received group desc stats reply is too short (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    if (*len < ntohs(src->length)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received group desc stats reply has invalid length (set to %u, but only %zu received).", ntohs(src->length), *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    if (ntohl(src->group_id) > OFPG_MAX) {
        if (errbuf != NULL) {
            char *gs = ofl_group_to_string(ntohl(src->group_id));
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received group desc stats has invalid group_id (%s).", gs);
            free(gs);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    dlen = ntohs(src->length) - sizeof(struct ofp_group_desc_stats);

    dm = (struct ofl_group_desc_stats *)malloc(sizeof(struct ofl_group_desc_stats));

    dm->type = src->type;
    dm->group_id = ntohl(src->group_id);

    error = ofl_utils_count_ofp_buckets(src->buckets, dlen, &dm->buckets_num, errbuf);
    if (error) {
        free(dm);
        return error;
    }
    dm->buckets = (struct ofl_bucket **)malloc(dm->buckets_num * sizeof(struct ofl_bucket *));

    bucket = src->buckets;
    for (i = 0; i < dm->buckets_num; i++) {
        error = ofl_structs_bucket_unpack(bucket, &dlen, dm->type, &(dm->buckets[i]), exp, errbuf);
        if (error) {
            OFL_UTILS_FREE_ARR_FUN3(dm->buckets, i,
                                    ofl_structs_free_bucket, exp, errbuf);
            free (dm);
            return error;
        }
        bucket = (struct ofp_bucket *)((uint8_t *)bucket + ntohs(bucket->len));
    }

    if (dlen != 0) {
        *len = *len - ntohs(src->length) + dlen;
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "The received group desc stats contained extra bytes (%zu).", dlen);
        }
        ofl_structs_free_group_desc_stats(dm, exp, NULL);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    *len -= ntohs(src->length);
    *dst = dm;
    return 0;
}

ofl_err
ofl_structs_bucket_counter_unpack(struct ofp_bucket_counter *src, size_t *len, struct ofl_bucket_counter **dst, char *errbuf) {
    struct ofl_bucket_counter *p;

    if (*len < sizeof(struct ofp_bucket_counter)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received bucket counter has invalid length (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_bucket_counter);

    p = (struct ofl_bucket_counter *)malloc(sizeof(struct ofl_bucket_counter));
    p->packet_count = ntoh64(src->packet_count);
    p->byte_count =   ntoh64(src->byte_count);

    *dst = p;
    return 0;
}

static ofl_err
ofl_structs_match_standard_unpack(struct ofp_match *src, size_t *len, struct ofl_match_standard **dst, char *errbuf) {
    struct ofl_match_standard *m;

    if (*len < OFPMT_STANDARD_LENGTH) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received standard match is too short (%zu).", *len);
        }
        return ofl_error(OFPET_BAD_MATCH, OFPBMC_BAD_LEN);
    }

    if (*len < ntohs(src->length)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received standard match has invalid length (set to %u, but only %zu received).", ntohs(src->length), *len);
        }
        return ofl_error(OFPET_BAD_MATCH, OFPBMC_BAD_LEN);
    }

    // NOTE: According to oftest/oft-1.1 VlanWildOutrange tests,
    //       VID is only to be tested if it is not wildcarded
    if (((ntohl(src->wildcards) & OFPFW_DL_VLAN) == 0) &&
            (ntohs(src->dl_vlan) != OFPVID_NONE) && (ntohs(src->dl_vlan) != OFPVID_ANY) &&
            (ntohs(src->dl_vlan) > VLAN_VID_MAX)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received match has invalid vlan vid (%u).", ntohs(src->dl_vlan));
        }
        return ofl_error(OFPET_BAD_MATCH, OFPBMC_BAD_VALUE);
    }

    // NOTE: According to oftest/oft-1.1 VlanWildOutrange tests,
    //       PCP is only to be tested if it is not wildcarded
    if (((ntohl(src->wildcards) & OFPFW_DL_VLAN_PCP) == 0) &&
           (src->dl_vlan_pcp > VLAN_PCP_MAX)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received match has invalid vlan pcp (%u).", src->dl_vlan_pcp);
        }
        return ofl_error(OFPET_BAD_MATCH, OFPBMC_BAD_VALUE);
    }

    // NOTE: According to oftest/oft-1.1 MplsWildLabelExactTcOutrange tests,
    //       Label is only to be tested if it is not wildcarded
    if (((ntohl(src->wildcards) & OFPFW_MPLS_LABEL) == 0) &&
            (ntohl(src->mpls_label) > MPLS_LABEL_MAX)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received match has invalid mpls label (%u).", ntohl(src->mpls_label));
        }
        return ofl_error(OFPET_BAD_MATCH, OFPBMC_BAD_VALUE);
    }

    // NOTE: According to oftest/oft-1.1 MplsWildLabelExactTcOutrange tests,
    //       TC is only to be tested if it is not wildcarded
    if (((ntohl(src->wildcards) & OFPFW_MPLS_TC) == 0) &&
            (src->mpls_tc > MPLS_TC_MAX)) {
        if (errbuf != NULL) {
            snprintf(errbuf, OFL_ERRBUF_SIZE, "Received match has invalid mpls tc (%u).", src->mpls_tc);
        }
        return ofl_error(OFPET_BAD_MATCH, OFPBMC_BAD_VALUE);
    }
    *len -= OFPMT_STANDARD_LENGTH;

    /* NOTE: According to 1.1 spec. only those protocols' fields should be
             taken into account, which are explicitly matched (MPLS, ARP, IP,
             TCP, UDP) It is up to the library user to handle this either by
             updating this match structure, or by other means. */
    m = (struct ofl_match_standard *)malloc(sizeof(struct ofl_match_standard));
    m->header.type =          OFPMT_STANDARD;
    m->in_port =       ntohl( src->in_port);
    m->wildcards =     ntohl( src->wildcards);

    /* ETH */
    memcpy(&(m->dl_src),      &(src->dl_src),      OFP_ETH_ALEN);
    memcpy(&(m->dl_src_mask), &(src->dl_src_mask), OFP_ETH_ALEN);
    memcpy(&(m->dl_dst),      &(src->dl_dst),      OFP_ETH_ALEN);
    memcpy(&(m->dl_dst_mask), &(src->dl_dst_mask), OFP_ETH_ALEN);

    /* VLAN */
    m->dl_vlan =              src->dl_vlan;
    m->dl_vlan_pcp =          src->dl_vlan_pcp;

    m->dl_type =              src->dl_type;

    /* IPv4 / ARP */
    m->nw_tos =               src->nw_tos;
    m->nw_proto =             src->nw_proto;
    m->nw_src =               src->nw_src;
    m->nw_src_mask =          src->nw_src_mask;
    m->nw_dst =               src->nw_dst;
    m->nw_dst_mask =          src->nw_dst_mask;

    /* Transport */
    m->tp_src =               src->tp_src;
    m->tp_dst =               src->tp_dst;

    /* MPLS */
    m->mpls_label =           src->mpls_label;
    m->mpls_tc =              src->mpls_tc;

    /* Metadata */
    m->metadata =             src->metadata;
    m->metadata_mask =        src->metadata_mask;

    *dst = m;
    return 0;
}

ofl_err
ofl_structs_match_unpack(struct ofp_match *src, size_t *len, struct ofl_match_header **dst, struct ofl_exp *exp, char *errbuf) {
    switch (ntohs(src->type)) {
        case (OFPMT_STANDARD): {
            return ofl_structs_match_standard_unpack(src, len, (struct ofl_match_standard **)dst, errbuf);
        }
        default: {
            if (exp == NULL || exp->match == NULL || exp->match->unpack == NULL) {
                if (errbuf != NULL) {
                    snprintf(errbuf, OFL_ERRBUF_SIZE, "Received match is experimental, but no callback was given.");
                }
                return ofl_error(OFPET_BAD_MATCH, OFPBMC_BAD_TYPE);
            }
            return exp->match->unpack(src, len, dst);
        }
    }
}
