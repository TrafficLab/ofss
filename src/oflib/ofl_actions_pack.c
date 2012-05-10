/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#include <netinet/in.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <openflow/openflow.h>
#include "ofl.h"
#include "ofl_utils.h"
#include "ofl_actions.h"
#include "ofl_structs.h"
#include "ofl_messages.h"

ssize_t
ofl_actions_ofp_len(struct ofl_action_header *action, struct ofl_exp *exp, char *errbuf) {
    switch (action->type) {
        case OFPAT_OUTPUT:
            return sizeof(struct ofp_action_output);
        case OFPAT_SET_VLAN_VID:
            return sizeof(struct ofp_action_vlan_vid);
        case OFPAT_SET_VLAN_PCP:
            return sizeof(struct ofp_action_vlan_pcp);
        case OFPAT_SET_DL_SRC:
        case OFPAT_SET_DL_DST:
            return sizeof(struct ofp_action_dl_addr);
        case OFPAT_SET_NW_SRC:
        case OFPAT_SET_NW_DST:
            return sizeof(struct ofp_action_nw_addr);
        case OFPAT_SET_NW_TOS:
            return sizeof(struct ofp_action_nw_tos);
        case OFPAT_SET_NW_ECN:
            return sizeof(struct ofp_action_nw_ecn);
        case OFPAT_SET_TP_SRC:
        case OFPAT_SET_TP_DST:
            return sizeof(struct ofp_action_tp_port);
        case OFPAT_COPY_TTL_OUT:
        case OFPAT_COPY_TTL_IN:
            return sizeof(struct ofp_action_header);
        case OFPAT_SET_MPLS_LABEL:
            return sizeof(struct ofp_action_mpls_label);
        case OFPAT_SET_MPLS_TC:
            return sizeof(struct ofp_action_mpls_tc);
        case OFPAT_SET_MPLS_TTL:
            return sizeof(struct ofp_action_mpls_ttl);
        case OFPAT_DEC_MPLS_TTL:
            return sizeof(struct ofp_action_header);
        case OFPAT_PUSH_VLAN:
            return sizeof(struct ofp_action_push);
        case OFPAT_POP_VLAN:
            return sizeof(struct ofp_action_header);
        case OFPAT_PUSH_MPLS:
            return sizeof(struct ofp_action_push);
        case OFPAT_POP_MPLS:
            return sizeof(struct ofp_action_pop_mpls);
        case OFPAT_SET_QUEUE:
            return sizeof(struct ofp_action_set_queue);
        case OFPAT_GROUP:
            return sizeof(struct ofp_action_group);
        case OFPAT_SET_NW_TTL:
            return sizeof(struct ofp_action_nw_ttl);
        case OFPAT_DEC_NW_TTL:
            return sizeof(struct ofp_action_header);
        case OFPAT_EXPERIMENTER: {
            if (exp == NULL || exp->act == NULL || exp->act->ofp_len == NULL) {
                if (errbuf != NULL) {
                    snprintf(errbuf, OFL_ERRBUF_SIZE, "requesting experimenter length, but no callback was given.");
                }
                return -1;
            }
            return exp->act->ofp_len(action);
        }
        default:
            return 0;
    }
}

size_t
ofl_actions_ofp_total_len(struct ofl_action_header **actions,
                          size_t actions_num, struct ofl_exp *exp, char *errbuf) {
    size_t sum;
    OFL_UTILS_SUM_ARR_FUN3(sum, actions, actions_num,
                           ofl_actions_ofp_len, exp, errbuf);
    return sum;
}

ssize_t
ofl_actions_pack(struct ofl_action_header *src, struct ofp_action_header *dst, struct ofl_exp *exp, char *errbuf) {

    dst->type = htons(src->type);
    memset(dst->pad, 0x00, 4);

    switch (src->type) {
        case OFPAT_OUTPUT: {
            struct ofl_action_output *sa = (struct ofl_action_output *)src;
            struct ofp_action_output *da = (struct ofp_action_output *)dst;

            da->len =     htons(sizeof(struct ofp_action_output));
            da->port =    htonl(sa->port);
            da->max_len = htons(sa->max_len);
            memset(da->pad, 0x00, 6);
            return sizeof(struct ofp_action_output);
        }
        case OFPAT_SET_VLAN_VID: {
            struct ofl_action_vlan_vid *sa = (struct ofl_action_vlan_vid *)src;
            struct ofp_action_vlan_vid *da = (struct ofp_action_vlan_vid *)dst;

            da->len =      htons(sizeof(struct ofp_action_vlan_vid));
            da->vlan_vid = sa->vlan_vid;
            memset(da->pad, 0x00, 2);
            return sizeof(struct ofp_action_vlan_vid);
        }
        case OFPAT_SET_VLAN_PCP: {
            struct ofl_action_vlan_pcp *sa = (struct ofl_action_vlan_pcp *)src;
            struct ofp_action_vlan_pcp *da = (struct ofp_action_vlan_pcp *)dst;

            da->len =      htons(sizeof(struct ofp_action_vlan_pcp));
            da->vlan_pcp = sa->vlan_pcp;
            memset(da->pad, 0x00, 3);
            return sizeof(struct ofp_action_vlan_pcp);
        }
        case OFPAT_SET_DL_SRC:
        case OFPAT_SET_DL_DST: {
            struct ofl_action_dl_addr *sa = (struct ofl_action_dl_addr *)src;
            struct ofp_action_dl_addr *da = (struct ofp_action_dl_addr *)dst;

            da->len = htons(sizeof(struct ofp_action_dl_addr));
            memcpy(&(da->dl_addr), &(sa->dl_addr), OFP_ETH_ALEN);
            memset(da->pad, 0x00, 6);
            return sizeof(struct ofp_action_dl_addr);
        }
        case OFPAT_SET_NW_SRC:
        case OFPAT_SET_NW_DST: {
            struct ofl_action_nw_addr *sa = (struct ofl_action_nw_addr *)src;
            struct ofp_action_nw_addr *da = (struct ofp_action_nw_addr *)dst;

            da->len =     htons(sizeof(struct ofp_action_nw_addr));
            da->nw_addr = sa->nw_addr;
            return sizeof(struct ofp_action_nw_addr);
        }
        case OFPAT_SET_NW_TOS: {
            struct ofl_action_nw_tos *sa = (struct ofl_action_nw_tos *)src;
            struct ofp_action_nw_tos *da = (struct ofp_action_nw_tos *)dst;

            da->len =    htons(sizeof(struct ofp_action_nw_tos));
            da->nw_tos = sa->nw_tos;
            memset(da->pad, 0x00, 3);
            return sizeof(struct ofp_action_nw_tos);
        }
        case OFPAT_SET_NW_ECN: {
            struct ofl_action_nw_ecn *sa = (struct ofl_action_nw_ecn *)src;
            struct ofp_action_nw_ecn *da = (struct ofp_action_nw_ecn *)dst;

            da->len =    htons(sizeof(struct ofp_action_nw_ecn));
            da->nw_ecn = sa->nw_ecn;
            memset(da->pad, 0x00, 3);
            return sizeof(struct ofp_action_nw_ecn);
        }
        case OFPAT_SET_TP_SRC:
        case OFPAT_SET_TP_DST: {
            struct ofl_action_tp_port *sa = (struct ofl_action_tp_port *)src;
            struct ofp_action_tp_port *da = (struct ofp_action_tp_port *)dst;

            da->len =     htons(sizeof(struct ofp_action_tp_port));
            da->tp_port = sa->tp_port;
            memset(da->pad, 0x00, 2);
            return sizeof(struct ofp_action_tp_port);
        }
        case OFPAT_COPY_TTL_OUT:
        case OFPAT_COPY_TTL_IN: {
            dst->len = htons(sizeof(struct ofp_action_header));
            return sizeof(struct ofp_action_header);
        }
        case OFPAT_SET_MPLS_LABEL: {
            struct ofl_action_mpls_label *sa = (struct ofl_action_mpls_label *)src;
            struct ofp_action_mpls_label *da = (struct ofp_action_mpls_label *)dst;

            da->len =        htons(sizeof(struct ofp_action_mpls_label));
            da->mpls_label = sa->mpls_label;
            return sizeof(struct ofp_action_mpls_label);
        }
        case OFPAT_SET_MPLS_TC: {
            struct ofl_action_mpls_tc *sa = (struct ofl_action_mpls_tc *)src;
            struct ofp_action_mpls_tc *da = (struct ofp_action_mpls_tc *)dst;

            da->len =     htons(sizeof(struct ofp_action_mpls_tc));
            da->mpls_tc = sa->mpls_tc;
            memset(da->pad, 0x00, 3);
            return sizeof(struct ofp_action_mpls_tc);
        }
        case OFPAT_SET_MPLS_TTL: {
            struct ofl_action_mpls_ttl *sa = (struct ofl_action_mpls_ttl *)src;
            struct ofp_action_mpls_ttl *da = (struct ofp_action_mpls_ttl *)dst;

            da->len =      htons(sizeof(struct ofp_action_mpls_ttl));
            da->mpls_ttl = sa->mpls_ttl;
            memset(da->pad, 0x00, 3);
            return sizeof(struct ofp_action_mpls_ttl);
        }
        case OFPAT_DEC_MPLS_TTL: {
            dst->len = htons(sizeof(struct ofp_action_header));
            return sizeof(struct ofp_action_header);
        }
        case OFPAT_PUSH_VLAN:
        case OFPAT_PUSH_MPLS: {
            struct ofl_action_push *sa = (struct ofl_action_push *)src;
            struct ofp_action_push *da = (struct ofp_action_push *)dst;

            da->len =       htons(sizeof(struct ofp_action_push));
            da->ethertype = sa->ethertype;
            memset(da->pad, 0x00, 2);
            return sizeof(struct ofp_action_push);
        }
        case OFPAT_POP_VLAN: {
            struct ofp_action_header *da = (struct ofp_action_header *)dst;

            da->len = htons(sizeof(struct ofp_action_header));
            return sizeof (struct ofp_action_header);
        }
        case OFPAT_POP_MPLS: {
            struct ofl_action_pop_mpls *sa = (struct ofl_action_pop_mpls *)src;
            struct ofp_action_pop_mpls *da = (struct ofp_action_pop_mpls *)dst;

            da->len =       htons(sizeof(struct ofp_action_pop_mpls));
            da->ethertype = sa->ethertype;
            memset(da->pad, 0x00, 2);
            return sizeof(struct ofp_action_pop_mpls);
        }
        case OFPAT_SET_QUEUE: {
            struct ofl_action_set_queue *sa = (struct ofl_action_set_queue *)src;
            struct ofp_action_set_queue *da = (struct ofp_action_set_queue *)dst;

            da->len =      htons(sizeof(struct ofp_action_set_queue));
            da->queue_id = htonl(sa->queue_id);
            return sizeof(struct ofp_action_set_queue);
        }
        case OFPAT_GROUP: {
            struct ofl_action_group *sa = (struct ofl_action_group *)src;
            struct ofp_action_group *da = (struct ofp_action_group *)dst;

            da->len =      htons(sizeof(struct ofp_action_group));
            da->group_id = htonl(sa->group_id);
            return sizeof(struct ofp_action_group);
        }
        case OFPAT_SET_NW_TTL: {
            struct ofl_action_set_nw_ttl *sa = (struct ofl_action_set_nw_ttl *)src;
            struct ofp_action_nw_ttl *da = (struct ofp_action_nw_ttl *)dst;

            da->len =    htons(sizeof(struct ofp_action_nw_ttl));
            da->nw_ttl = sa->nw_ttl;
            memset(da->pad, 0x00, 3);
            return sizeof(struct ofp_action_nw_ttl);
        }
        case OFPAT_DEC_NW_TTL: {
            dst->len = htons(sizeof(struct ofp_action_header));
            return sizeof(struct ofp_action_header);
        }
        case OFPAT_EXPERIMENTER: {
            if (exp == NULL || exp->act == NULL || exp->act->pack == NULL) {
                if (errbuf != NULL) {
                    snprintf(errbuf, OFL_ERRBUF_SIZE, "Trying to pack experimenter, but no callback was given.");
                }
                return -1;
            }
            return exp->act->pack(src, dst);
        }
        default:
            return -1;
    };

    // should not happen
    return -1;
}
