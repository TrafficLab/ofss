/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <openflow/openflow.h>
#include "ofl.h"
#include "ofl_print.h"
#include "ofl_actions.h"
#include "ofl_packets.h"


#define ETH_ADDR_FMT                                                    \
    "%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8
#define ETH_ADDR_ARGS(ea)                                   \
    (ea)[0], (ea)[1], (ea)[2], (ea)[3], (ea)[4], (ea)[5]

#define IP_FMT "%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8
#define IP_ARGS(ip)                             \
        ((uint8_t *) ip)[0],                    \
        ((uint8_t *) ip)[1],                    \
        ((uint8_t *) ip)[2],                    \
        ((uint8_t *) ip)[3]


char *
ofl_action_to_string(struct ofl_action_header *act, struct ofl_exp *exp) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_action_print(stream, act, exp);
    fclose(stream);
    return str;
}

void
ofl_action_print(FILE *stream, struct ofl_action_header *act, struct ofl_exp *exp) {

    ofl_action_type_print(stream, act->type);

    switch (act->type) {
        case OFPAT_OUTPUT: {
            struct ofl_action_output *a = (struct ofl_action_output *)act;

            fprintf(stream, "{port=\"");
            ofl_port_print(stream, a->port);
            if (a->port == OFPP_CONTROLLER) {
                fprintf(stream, "\", mlen=\"%u\"}", a->max_len);
            } else {
                fprintf(stream, "\"}");
            }
            break;
        }
        case OFPAT_SET_VLAN_VID: {
            struct ofl_action_vlan_vid *a = (struct ofl_action_vlan_vid *)act;

            fprintf(stream, "{vid=\"");
            ofl_vlan_vid_print(stream, ntohs(a->vlan_vid));
            fprintf(stream, "\"}");
            break;
        }
        case OFPAT_SET_VLAN_PCP: {
            struct ofl_action_vlan_pcp *a = (struct ofl_action_vlan_pcp *)act;

            fprintf(stream, "{pcp=\"%u\"}", a->vlan_pcp);
            break;
        }
        case OFPAT_SET_DL_SRC:
        case OFPAT_SET_DL_DST: {
            struct ofl_action_dl_addr *a = (struct ofl_action_dl_addr *)act;

            fprintf(stream, "{addr=\""ETH_ADDR_FMT"\"}", ETH_ADDR_ARGS(a->dl_addr));
            break;
        }
        case OFPAT_SET_NW_SRC:
        case OFPAT_SET_NW_DST: {
            struct ofl_action_nw_addr *a = (struct ofl_action_nw_addr *)act;

            fprintf(stream, "{addr=\""IP_FMT"\"}", IP_ARGS(&a->nw_addr));
            break;
        }
        case OFPAT_SET_NW_TOS: {
            struct ofl_action_nw_tos *a = (struct ofl_action_nw_tos *)act;

            fprintf(stream, "{tos=\"0x%02"PRIx8"\"}", a->nw_tos);
            break;
        }
        case OFPAT_SET_NW_ECN: {
            struct ofl_action_nw_ecn *a = (struct ofl_action_nw_ecn *)act;

            fprintf(stream, "{ecn=\"%u\"}", a->nw_ecn);
            break;
        }
        case OFPAT_SET_TP_SRC:
        case OFPAT_SET_TP_DST: {
            struct ofl_action_tp_port *a = (struct ofl_action_tp_port *)act;

            fprintf(stream, "{port=\"%u\"}", ntohs(a->tp_port));
            break;
        }
        case OFPAT_COPY_TTL_OUT:
        case OFPAT_COPY_TTL_IN: {
            break;
        }
        case OFPAT_SET_MPLS_LABEL: {
            struct ofl_action_mpls_label *a = (struct ofl_action_mpls_label *)act;

            fprintf(stream, "{label=\"%"PRIu32"\"}", ntohl(a->mpls_label));
            break;
        }
        case OFPAT_SET_MPLS_TC: {
            struct ofl_action_mpls_tc *a = (struct ofl_action_mpls_tc *)act;

            fprintf(stream, "{tc=\"%u\"}", a->mpls_tc);
            break;
        }
        case OFPAT_SET_MPLS_TTL: {
            struct ofl_action_mpls_ttl *a = (struct ofl_action_mpls_ttl *)act;

            fprintf(stream, "{ttl=\"%u\"}", a->mpls_ttl);
            break;
        }
        case OFPAT_DEC_MPLS_TTL: {
            break;
        }
        case OFPAT_PUSH_VLAN:
        case OFPAT_PUSH_MPLS: {
            struct ofl_action_push *a = (struct ofl_action_push *)act;

            fprintf(stream, "{eth=\"0x%04"PRIx16"\"}", ntohs(a->ethertype));
            break;
        }
        case OFPAT_POP_VLAN: {
            break;
        }
        case OFPAT_POP_MPLS: {
            struct ofl_action_pop_mpls *a = (struct ofl_action_pop_mpls *)act;

            fprintf(stream, "{eth=\"0x%04"PRIx16"\"}", ntohs(a->ethertype));
            break;
        }
        case OFPAT_SET_QUEUE: {
            struct ofl_action_set_queue *a = (struct ofl_action_set_queue *)act;

            fprintf(stream, "{q=\"");
            ofl_queue_print(stream, a->queue_id);
            fprintf(stream, "\"}");
            break;
        }
        case OFPAT_GROUP: {
            struct ofl_action_group *a = (struct ofl_action_group *)act;

            fprintf(stream, "{id=\"");
            ofl_group_print(stream, a->group_id);
            fprintf(stream, "\"}");

            break;
        }
        case OFPAT_SET_NW_TTL: {
            struct ofl_action_set_nw_ttl *a = (struct ofl_action_set_nw_ttl *)act;

            fprintf(stream, "{ttl=\"%u\"}", a->nw_ttl);
            break;
        }
        case OFPAT_DEC_NW_TTL: {
            break;
        }
        case OFPAT_EXPERIMENTER: {
            if (exp == NULL || exp->act == NULL || exp->act->to_string == NULL) {
                struct ofl_action_experimenter *a = (struct ofl_action_experimenter *)act;

                fprintf(stream, "{id=\"0x%"PRIx32"\"}", a->experimenter_id);
            } else {
                char *c = exp->act->to_string(act);
                fprintf(stream, "%s", c);
                free (c);
            }
            break;
        }
    }
}
