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
#include "ofl.h"
#include "ofl_actions.h"

int
ofl_actions_free(struct ofl_action_header *act, struct ofl_exp *exp, char *errbuf) {
    switch (act->type) {
        case OFPAT_OUTPUT:
        case OFPAT_SET_VLAN_VID:
        case OFPAT_SET_VLAN_PCP:
        case OFPAT_SET_DL_SRC:
        case OFPAT_SET_DL_DST:
        case OFPAT_SET_NW_SRC:
        case OFPAT_SET_NW_DST:
        case OFPAT_SET_NW_TOS:
        case OFPAT_SET_NW_ECN:
        case OFPAT_SET_TP_SRC:
        case OFPAT_SET_TP_DST:
        case OFPAT_COPY_TTL_OUT:
        case OFPAT_COPY_TTL_IN:
        case OFPAT_SET_MPLS_LABEL:
        case OFPAT_SET_MPLS_TC:
        case OFPAT_SET_MPLS_TTL:
        case OFPAT_DEC_MPLS_TTL:
        case OFPAT_PUSH_VLAN:
        case OFPAT_POP_VLAN:
        case OFPAT_PUSH_MPLS:
        case OFPAT_POP_MPLS:
        case OFPAT_SET_QUEUE:
        case OFPAT_GROUP:
        case OFPAT_SET_NW_TTL:
        case OFPAT_DEC_NW_TTL: {
            break;
        }
        case OFPAT_EXPERIMENTER: {
            if (exp == NULL || exp->act == NULL || exp->act->free == NULL) {
                if (errbuf != NULL) {
                    snprintf(errbuf, OFL_ERRBUF_SIZE, "Freeing experimenter action, but no callback is given.");
                    free(act);
                    return -1;
                }
            }
            exp->act->free(act);
            return 0;
        }
        default: {
            break;
        }
    }
    free(act);
    return 0;
}

ofl_err
ofl_utils_count_ofp_actions(void *data, size_t data_len, size_t *count, char *errbuf) {
    struct ofp_action_header *act;
    uint8_t *d;

    d = (uint8_t *)data;
    *count = 0;

    /* this is needed so that buckets are handled correctly */
    while (data_len >= sizeof(struct ofp_action_header)) {
        act = (struct ofp_action_header *)d;

        if (data_len < ntohs(act->len) || ntohs(act->len) < sizeof(struct ofp_action_header)) {
            if (errbuf != NULL) {
                snprintf(errbuf, OFL_ERRBUF_SIZE, "Received action has invalid length.");
            }
            return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
        }
        data_len -= ntohs(act->len);
        d += ntohs(act->len);
        (*count)++;
    }

    return 0;
}


struct ofl_action_header *
ofl_actions_clone(struct ofl_action_header *action, struct ofl_exp *exp, char *errbuf) {
    switch (action->type) {
        case OFPAT_OUTPUT: {
            return memcpy(malloc(sizeof(struct ofl_action_output)), action,
                            sizeof(struct ofl_action_output));
        }
        case OFPAT_SET_VLAN_VID: {
            return memcpy(malloc(sizeof(struct ofl_action_vlan_vid)), action,
                            sizeof(struct ofl_action_vlan_vid));
        }
        case OFPAT_SET_VLAN_PCP: {
            return memcpy(malloc(sizeof(struct ofl_action_vlan_pcp)), action,
                            sizeof(struct ofl_action_vlan_pcp));
        }

        case OFPAT_SET_DL_SRC:
        case OFPAT_SET_DL_DST: {
            return memcpy(malloc(sizeof(struct ofl_action_dl_addr)), action,
                            sizeof(struct ofl_action_dl_addr));
        }

        case OFPAT_SET_NW_SRC:
        case OFPAT_SET_NW_DST: {
            return memcpy(malloc(sizeof(struct ofl_action_nw_addr)), action,
                            sizeof(struct ofl_action_nw_addr));
        }
        case OFPAT_SET_NW_TOS: {
            return memcpy(malloc(sizeof(struct ofl_action_nw_tos)), action,
                            sizeof(struct ofl_action_nw_tos));
        }

        case OFPAT_SET_NW_ECN: {
            return memcpy(malloc(sizeof(struct ofl_action_nw_ecn)), action,
                            sizeof(struct ofl_action_nw_ecn));
        }

        case OFPAT_SET_TP_SRC:
        case OFPAT_SET_TP_DST: {
            return memcpy(malloc(sizeof(struct ofl_action_tp_port)), action,
                            sizeof(struct ofl_action_tp_port));
        }

        case OFPAT_COPY_TTL_OUT: {
            return memcpy(malloc(sizeof(struct ofl_action_header)), action,
                            sizeof(struct ofl_action_header));
        }

        case OFPAT_COPY_TTL_IN: {
            return memcpy(malloc(sizeof(struct ofl_action_header)), action,
                            sizeof(struct ofl_action_header));
        }

        case OFPAT_SET_MPLS_LABEL: {
            return memcpy(malloc(sizeof(struct ofl_action_mpls_label)), action,
                            sizeof(struct ofl_action_mpls_label));
        }

        case OFPAT_SET_MPLS_TC: {
            return memcpy(malloc(sizeof(struct ofl_action_mpls_tc)), action,
                            sizeof(struct ofl_action_mpls_tc));
        }

        case OFPAT_SET_MPLS_TTL: {
            return memcpy(malloc(sizeof(struct ofl_action_mpls_ttl)), action,
                            sizeof(struct ofl_action_mpls_ttl));
        }

        case OFPAT_DEC_MPLS_TTL: {
            return memcpy(malloc(sizeof(struct ofl_action_header)), action,
                            sizeof(struct ofl_action_header));
        }

        case OFPAT_PUSH_VLAN:
        case OFPAT_PUSH_MPLS: {
            return memcpy(malloc(sizeof(struct ofl_action_push)), action,
                            sizeof(struct ofl_action_push));
        }

        case OFPAT_POP_VLAN: {
            return memcpy(malloc(sizeof(struct ofl_action_header)), action,
                            sizeof(struct ofl_action_header));
        }

        case OFPAT_POP_MPLS: {
            return memcpy(malloc(sizeof(struct ofl_action_pop_mpls)), action,
                            sizeof(struct ofl_action_pop_mpls));
        }

        case OFPAT_SET_QUEUE: {
            return memcpy(malloc(sizeof(struct ofl_action_set_queue)), action,
                            sizeof(struct ofl_action_set_queue));
        }

        case OFPAT_GROUP: {
            return memcpy(malloc(sizeof(struct ofl_action_group)), action,
                            sizeof(struct ofl_action_group));
        }

        case OFPAT_SET_NW_TTL: {
            return memcpy(malloc(sizeof(struct ofl_action_set_nw_ttl)), action,
                            sizeof(struct ofl_action_set_nw_ttl));
        }

        case OFPAT_DEC_NW_TTL: {
            return memcpy(malloc(sizeof(struct ofl_action_header)), action,
                            sizeof(struct ofl_action_header));
        }

        case OFPAT_EXPERIMENTER: {
            if (exp == NULL || exp->act == NULL || exp->act->clone == NULL) {
                if (errbuf != NULL) {
                    snprintf(errbuf, OFL_ERRBUF_SIZE, "Cloning EXPERIMENTER action, but no callback is given.");
                }
                return NULL;
            }

            return exp->act->clone(action);
        }
    }

    if (errbuf != NULL) {
        snprintf(errbuf, OFL_ERRBUF_SIZE, "Cloning unknown action type.");
    }
    return NULL;

}
