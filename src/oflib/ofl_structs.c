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
#include "lib/compiler.h"
#include "ofl.h"
#include "ofl_structs.h"
#include "ofl_actions.h"
#include "ofl_utils.h"

ofl_err
ofl_utils_count_ofp_instructions(void *data, size_t data_len, size_t *count, char *errbuf) {
    struct ofp_instruction *inst;
    uint8_t *d;

    d = (uint8_t *)data;
    *count = 0;

    /* this is needed so that buckets are handled correctly */
    while (data_len >= sizeof(struct ofp_instruction)) {
        inst = (struct ofp_instruction *)d;

        if (data_len < ntohs(inst->len) || ntohs(inst->len) < sizeof(struct ofp_instruction)) {
            if (errbuf != NULL) {
                snprintf(errbuf, OFL_ERRBUF_SIZE, "Received instruction has invalid length.");
            }
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        }
        data_len -= ntohs(inst->len);
        d += ntohs(inst->len);
        (*count)++;
    }

    return 0;
}


ofl_err
ofl_utils_count_ofp_buckets(void *data, size_t data_len, size_t *count, char *errbuf) {
    struct ofp_bucket *bucket;
    uint8_t *d;

    d = (uint8_t *)data;
    *count = 0;

    while (data_len >= sizeof(struct ofp_bucket)) {
        bucket = (struct ofp_bucket *)d;

        if (data_len < ntohs(bucket->len) || ntohs(bucket->len) < sizeof(struct ofp_bucket)) {
            if (errbuf != NULL) {
                snprintf(errbuf, OFL_ERRBUF_SIZE, "Received bucket has invalid length.");
            }
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        }
        data_len -= ntohs(bucket->len);
        d += ntohs(bucket->len);
        (*count)++;
    }

    return 0;
}


ofl_err
ofl_utils_count_ofp_ports(void *data UNUSED_ATTR, size_t data_len, size_t *count) {
    *count = data_len / sizeof(struct ofp_port);
    return 0;
}


ofl_err
ofl_utils_count_ofp_packet_queues(void *data, size_t data_len, size_t *count, char *errbuf) {
    struct ofp_packet_queue *queue;
    uint8_t *d;

    d = (uint8_t *)data;
    *count = 0;

    while (data_len >= sizeof(struct ofp_packet_queue)) {
        queue = (struct ofp_packet_queue *)d;

        if (data_len < ntohs(queue->len) || ntohs(queue->len) < sizeof(struct ofp_packet_queue)) {
            if (errbuf != NULL) {
                snprintf(errbuf, OFL_ERRBUF_SIZE, "Received queue has invalid length.");
            }
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        }
        data_len -= ntohs(queue->len);
        d += ntohs(queue->len);
        (*count)++;
    }

    return 0;

}

ofl_err
ofl_utils_count_ofp_flow_stats(void *data, size_t data_len, size_t *count, char *errbuf) {
    struct ofp_flow_stats *stat;
    uint8_t *d;

    d = (uint8_t *)data;
    *count = 0;

    while (data_len >= sizeof(struct ofp_flow_stats)) {
        stat = (struct ofp_flow_stats *)d;

        if (data_len < ntohs(stat->length) || ntohs(stat->length) < sizeof(struct ofp_flow_stats)) {
            if (errbuf != NULL) {
                snprintf(errbuf, OFL_ERRBUF_SIZE, "Received flow stat has invalid length.");
            }
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        }
        data_len -= ntohs(stat->length);
        d += ntohs(stat->length);
        (*count)++;
    }

    return 0;
}

ofl_err
ofl_utils_count_ofp_group_stats(void *data, size_t data_len, size_t *count, char *errbuf) {
    struct ofp_group_stats *stat;
    uint8_t *d;

    d = (uint8_t *)data;
    *count = 0;

    while (data_len >= sizeof(struct ofp_group_stats)) {
        stat = (struct ofp_group_stats *)d;

        if (data_len < ntohs(stat->length) || ntohs(stat->length) < sizeof(struct ofp_group_stats)) {
            if (errbuf != NULL) {
                snprintf(errbuf, OFL_ERRBUF_SIZE, "Received group stat has invalid length.");
            }
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        }
        data_len -= ntohs(stat->length);
        d += ntohs(stat->length);
        (*count)++;
    }

    return 0;
}


ofl_err
ofl_utils_count_ofp_table_stats(void *data UNUSED_ATTR, size_t data_len, size_t *count) {
    *count = data_len / sizeof(struct ofp_table_stats);
    return 0;

}

ofl_err
ofl_utils_count_ofp_bucket_counters(void *data UNUSED_ATTR, size_t data_len, size_t *count) {
    *count = data_len / sizeof(struct ofp_bucket_counter);
    return 0;
}

ofl_err
ofl_utils_count_ofp_port_stats(void *data UNUSED_ATTR, size_t data_len, size_t *count) {
    *count = data_len / sizeof(struct ofp_port_stats);
    return 0;
}

ofl_err
ofl_utils_count_ofp_queue_stats(void *data UNUSED_ATTR, size_t data_len, size_t *count) {
    *count = data_len / sizeof(struct ofp_queue_stats);
    return 0;
}

ofl_err
ofl_utils_count_ofp_group_desc_stats(void *data, size_t data_len, size_t *count, char *errbuf) {
    struct ofp_group_desc_stats *stat;
    uint8_t *d;

    d = (uint8_t *)data;
    *count = 0;

    while (data_len >= sizeof(struct ofp_group_desc_stats)) {
        stat = (struct ofp_group_desc_stats *)d;

        if (data_len < ntohs(stat->length) || ntohs(stat->length) < sizeof(struct ofp_group_desc_stats)) {
            if (errbuf != NULL) {
                snprintf(errbuf, OFL_ERRBUF_SIZE, "Received group desc stat has invalid length.");
            }
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        }
        data_len -= ntohs(stat->length);
        d += ntohs(stat->length);
        (*count)++;
    }

    return 0;
}

ofl_err
ofl_utils_count_ofp_queue_props(void *data, size_t data_len, size_t *count, char *errbuf) {
    struct ofp_queue_prop_header *prop;
    uint8_t *d;

    d = (uint8_t *)data;
    (*count) = 0;

    while (data_len >= sizeof(struct ofp_queue_prop_header)) {
        prop = (struct ofp_queue_prop_header *)d;

        if (data_len < ntohs(prop->len) || ntohs(prop->len) < sizeof(struct ofp_queue_prop_header)) {
            if (errbuf != NULL) {
                snprintf(errbuf, OFL_ERRBUF_SIZE, "Received queue prop has invalid length.");
            }
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        }
        data_len -= ntohs(prop->len);
        d += ntohs(prop->len);
        (*count)++;
    }

    return 0;
}


void
ofl_structs_free_packet_queue(struct ofl_packet_queue *queue) {
    OFL_UTILS_FREE_ARR(queue->properties, queue->properties_num);
    free(queue);
}

int
ofl_structs_free_instruction(struct ofl_instruction_header *inst, struct ofl_exp *exp, char *errbuf) {
    switch (inst->type) {
        case OFPIT_GOTO_TABLE:
        case OFPIT_WRITE_METADATA:
            break;
        case OFPIT_WRITE_ACTIONS:
        case OFPIT_APPLY_ACTIONS: {
            struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)inst;
            OFL_UTILS_FREE_ARR_FUN3(ia->actions, ia->actions_num,
                                    ofl_actions_free, exp, errbuf);
            break;
        }
        case OFPIT_CLEAR_ACTIONS: {
            break;
        }
        case OFPIT_EXPERIMENTER: {
            if (exp == NULL || exp->inst == NULL || exp->inst->free == NULL) {
                if (errbuf != NULL) {
                    snprintf(errbuf, OFL_ERRBUF_SIZE, "Trying to free experimented instruction, but no callback was given.");
                }
                return -1;
            } else {
                return exp->inst->free(inst);
            }
            break;
        }
    }
    free(inst);
    return 0;
}

void
ofl_structs_free_table_stats(struct ofl_table_stats *stats) {
    free(stats->name);
    free(stats);
}

void
ofl_structs_free_bucket(struct ofl_bucket *bucket, struct ofl_exp *exp, char *errbuf) {
    OFL_UTILS_FREE_ARR_FUN3(bucket->actions, bucket->actions_num,
                            ofl_actions_free, exp, errbuf);
    free(bucket);
}


void
ofl_structs_free_flow_stats(struct ofl_flow_stats *stats, struct ofl_exp *exp, char *errbuf) {
    OFL_UTILS_FREE_ARR_FUN3(stats->instructions, stats->instructions_num,
                            ofl_structs_free_instruction, exp, errbuf);
    ofl_structs_free_match(stats->match, exp, errbuf);
    //TODO error
    free(stats);
}

void
ofl_structs_free_port(struct ofl_port *port) {
    free(port->name);
    free(port);
}

void
ofl_structs_free_group_stats(struct ofl_group_stats *stats) {
    OFL_UTILS_FREE_ARR(stats->counters, stats->counters_num);
    free(stats);
}

void
ofl_structs_free_group_desc_stats(struct ofl_group_desc_stats *stats, struct ofl_exp *exp, char *errbuf) {
    OFL_UTILS_FREE_ARR_FUN3(stats->buckets, stats->buckets_num,
                            ofl_structs_free_bucket, exp, errbuf);
    //TODO error
    free(stats);
}

int
ofl_structs_free_match(struct ofl_match_header *match, struct ofl_exp *exp, char *errbuf) {
    switch (match->type) {
        case (OFPMT_STANDARD): {
            free(match);
            break;
        }
        default: {
            if (exp == NULL || exp->match == NULL || exp->match->free == NULL) {
                if (errbuf != NULL) {
                    snprintf(errbuf, OFL_ERRBUF_SIZE, "Trying to free experimented instruction, but no callback was given.");
                }
                free(match);
                return -1;
            } else {
                return exp->match->free(match);
            }
            break;
        }
    }
    return 0;
}

struct ofl_instruction_header *
ofl_structs_instruction_clone(struct ofl_instruction_header *inst, struct ofl_exp *exp, char *errbuf) {
    switch (inst->type) {
        case OFPIT_GOTO_TABLE:
            return memcpy(malloc(sizeof(struct ofl_instruction_goto_table)), inst,
                                        sizeof(struct ofl_instruction_goto_table));
        case OFPIT_WRITE_METADATA:
            return memcpy(malloc(sizeof(struct ofl_instruction_write_metadata)), inst,
                                        sizeof(struct ofl_instruction_write_metadata));
        case OFPIT_WRITE_ACTIONS:
        case OFPIT_APPLY_ACTIONS: {
            struct ofl_instruction_actions *o = (struct ofl_instruction_actions *)inst;
            struct ofl_instruction_actions *c = memcpy(malloc(sizeof(struct ofl_instruction_actions)), inst,
                                                sizeof(struct ofl_instruction_actions));
            c->actions = malloc(sizeof(struct ofl_action_header *) * c->actions_num);
            size_t i;
            for(i=0; i<c->actions_num; i++) {
                c->actions[i] = ofl_actions_clone(o->actions[i], exp, errbuf);
                //TODO error
            }
            return (struct ofl_instruction_header *)c;
        }
        case OFPIT_CLEAR_ACTIONS: {
            return memcpy(malloc(sizeof(struct ofl_instruction_actions)), inst,
                                        sizeof(struct ofl_instruction_actions));
        }
        case OFPIT_EXPERIMENTER: {
            if (exp == NULL || exp->inst == NULL || exp->inst->clone == NULL) {
                if (errbuf != NULL) {
                    snprintf(errbuf, OFL_ERRBUF_SIZE, "Trying to clone experimenter instruction, but no callback was given.");
                }
                return NULL;
            }

            return exp->inst->clone(inst);
        }
    }

    if (errbuf != NULL) {
        snprintf(errbuf, OFL_ERRBUF_SIZE, "Trying to clone unknown instruction.");
    }
    return NULL;
}

struct ofl_bucket *
ofl_structs_bucket_clone(struct ofl_bucket *bucket, struct ofl_exp *exp, char *errbuf) {
    struct ofl_bucket *clone = memcpy(malloc(sizeof(struct ofl_bucket)), bucket, sizeof(struct ofl_bucket));
    clone->actions = malloc(sizeof(struct ofl_bucket *) * clone->actions_num);
    size_t i;
    for (i=0; i<clone->actions_num; i++) {
        clone->actions[i] = ofl_actions_clone(bucket->actions[i], exp, errbuf);
    }

    return clone;
}
