/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef OFL_ACTIONS_H
#define OFL_ACTIONS_H 1

#include <sys/types.h>
#include <stdio.h>
#include <openflow/openflow.h>
#include "ofl.h"

struct ofl_exp;

void
ofl_actions_pack_init();
void
ofl_actions_unpack_init();
void
ofl_actions_init();

/****************************************************************************
 * Action structure definitions
 ****************************************************************************/

/* Common header for actions. All action structures - including experimenter
 * ones - must start with this header. */
struct ofl_action_header {
    enum ofp_action_type   type;   /* One of OFPAT_*. */
};


struct ofl_action_output {
    struct ofl_action_header   header; /* OFPAT_OUTPUT. */

    uint32_t   port;    /* Output port. */
    uint16_t   max_len; /* Max length to send to controller. */
};

struct ofl_action_vlan_vid {
    struct ofl_action_header   header; /* OFPAT_SET_VLAN_VID. */

    uint16_t   vlan_vid; /* VLAN id. (N.B.O.) */
};

struct ofl_action_vlan_pcp {
        struct ofl_action_header   header; /* OFPAT_SET_VLAN_PCP. */

    uint8_t   vlan_pcp; /* VLAN priority. */
};

struct ofl_action_dl_addr {
    struct ofl_action_header   header; /* OFPAT_SET_DL_SRC/DST. */

    uint8_t   dl_addr[OFP_ETH_ALEN]; /* Ethernet address. */
};

struct ofl_action_nw_addr {
    struct ofl_action_header   header; /* OFPAT_SET_NW_SRC/DST. */

    uint32_t   nw_addr;   /*  (N.B.O.) */
};

struct ofl_action_nw_tos {
    struct ofl_action_header   header; /* OFPAT_SET_NW_TOS. */

    uint8_t   nw_tos;
};

struct ofl_action_nw_ecn {
    struct ofl_action_header   header; /* OFPAT_SET_NW_ECN. */

    uint8_t   nw_ecn;
};

struct ofl_action_tp_port {
    struct ofl_action_header   header; /* OFPAT_SET_TP_SRC/DST. */

    uint16_t   tp_port; /* TCP/UDP/SCTP port. (N.B.O.) */
};

struct ofl_action_mpls_label {
    struct ofl_action_header   header; /* OFPAT_SET_MPLS_LABEL. */

    uint32_t   mpls_label; /* MPLS label. (N.B.O.) */
};

struct ofl_action_mpls_tc {
    struct ofl_action_header   header; /* OFPAT_SET_MPLS_TC. */

    uint8_t   mpls_tc; /* MPLS TC */
};

struct ofl_action_mpls_ttl {
    struct ofl_action_header   header; /* OFPAT_SET_MPLS_TTL. */

    uint8_t   mpls_ttl; /* MPLS TTL */
};

struct ofl_action_push {
    struct ofl_action_header   header; /* OFPAT_PUSH_VLAN/MPLS. */

    uint16_t   ethertype; /* Ethertype. (N.B.O.) */
};

struct ofl_action_pop_mpls {
    struct ofl_action_header   header; /* OFPAT_POP_MPLS. */

    uint16_t   ethertype; /* Ethertype. (N.B.O.) */
};

struct ofl_action_set_queue {
    struct ofl_action_header   header; /* OFPAT_SET_QUEUE. */

    uint32_t   queue_id;
};

struct ofl_action_set_nw_ttl {
    struct ofl_action_header   header; /* OFPAT_SET_NW_TTL. */

    uint8_t   nw_ttl;
};

struct ofl_action_group {
    struct ofl_action_header   header; /* OFPAT_GROUP. */

    uint32_t   group_id;  /* Group identifier. */
};

struct ofl_action_experimenter {
    struct ofl_action_header   header; /* OFPAT_EXPERIMENTER. */

    uint32_t  experimenter_id; /* Experimenter ID */
};


/****************************************************************************
 * Functions for (un)packing action structures
 ****************************************************************************/

/* Packs the action in src to the memory location beginning at the address
 * pointed at by dst. The return value is the length of the resulted structure.
 * In case of an experimenter action, it uses the passed in experimenter
 * callback. */
ssize_t
ofl_actions_pack(struct ofl_action_header *src, struct ofp_action_header *dst, struct ofl_exp *exp, char *errbuf);


/* Given a list of action in OpenFlow wire format, these function returns
 * the count of those actions in the passed in byte array. The functions
 * return an ofl_err in case of an error, or 0 on succes. */
ofl_err
ofl_utils_count_ofp_actions(void *data, size_t data_len, size_t *count, char *errbuf);


/* Unpacks the wire format action in src to a new memory location and returns a
 * pointer to the location in dst. Returns 0 on success. In case of an
 * experimenter action, it uses the passed in experimenter callback. */
ofl_err
ofl_actions_unpack(struct ofp_action_header *src, size_t *len, struct ofl_action_header **dst, struct ofl_exp *exp, char *errbuf);



/****************************************************************************
 * Functions for freeing action structures
 ****************************************************************************/

/* Calling this function frees the passed in action structure. In case of an
 * experimenter action, it uses the passed in experimenter callback. */
int
ofl_actions_free(struct ofl_action_header *act, struct ofl_exp *exp, char *errbuf);



/****************************************************************************
 * Utilities
 ****************************************************************************/

/* Returns the length of the resulting OpenFlow action structure from
 * converting the passed in action. In case of an experimenter action, it uses
 * the passed in experimenter callback. */
size_t
ofl_actions_ofp_total_len(struct ofl_action_header **actions, size_t actions_num, struct ofl_exp *exp, char *errbuf);

/* Returns the length of the resulting OpenFlow action structures from
 * converting the passed in list of actions. In case of an experimenter action,
 * it uses the passed in experimenter callback. */
ssize_t
ofl_actions_ofp_len(struct ofl_action_header *action, struct ofl_exp *exp, char *errbuf);

struct ofl_action_header *
ofl_actions_clone(struct ofl_action_header *action, struct ofl_exp *exp, char *errbuf);



/****************************************************************************
 * Functions for printing actions
 ****************************************************************************/

/* Converts the passed in action to a string format. In case of an experimenter
 * action, it uses the passed in experimenter callback. */
char *
ofl_action_to_string(struct ofl_action_header *act, struct ofl_exp *exp);

/* Converts the passed in action to a string format and adds it to the dynamic
 * string. In case of an experimenter action, it uses the passed in
 * experimenter callback. */
void
ofl_action_print(FILE *stream, struct ofl_action_header *act, struct ofl_exp *exp);



#endif /* OFL_ACTIONS */
