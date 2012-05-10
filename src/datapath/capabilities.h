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
 * Structures describing the capabilities of the DP.
 */

#ifndef CAPABILITIES_H
#define CAPABILITIES_H 1

#include <openflow/openflow.h>

#define DP_CAPABILITIES ( OFPC_FLOW_STATS        \
                        | OFPC_TABLE_STATS          \
                        | OFPC_PORT_STATS           \
                        | OFPC_GROUP_STATS          \
                     /* | OFPC_IP_REASM       */    \
                        | OFPC_QUEUE_STATS          \
                        | OFPC_ARP_MATCH_IP )

#define DP_INSTRUCTIONS ( (1 << OFPIT_GOTO_TABLE)         \
                        | (1 << OFPIT_WRITE_METADATA)     \
                        | (1 << OFPIT_WRITE_ACTIONS)      \
                        | (1 << OFPIT_APPLY_ACTIONS)      \
                        | (1 << OFPIT_CLEAR_ACTIONS) )

#define DP_ACTIONS ( (1 << OFPAT_OUTPUT)          \
                   | (1 << OFPAT_SET_VLAN_VID)    \
                   | (1 << OFPAT_SET_VLAN_PCP)    \
                   | (1 << OFPAT_SET_DL_SRC)      \
                   | (1 << OFPAT_SET_DL_DST)      \
                   | (1 << OFPAT_SET_NW_SRC)      \
                   | (1 << OFPAT_SET_NW_DST)      \
                   | (1 << OFPAT_SET_NW_TOS)      \
                   | (1 << OFPAT_SET_NW_ECN)      \
                   | (1 << OFPAT_SET_TP_SRC)      \
                   | (1 << OFPAT_SET_TP_DST)      \
                   | (1 << OFPAT_COPY_TTL_OUT)    \
                   | (1 << OFPAT_COPY_TTL_IN)     \
                   | (1 << OFPAT_SET_MPLS_LABEL)  \
                   | (1 << OFPAT_SET_MPLS_TC)     \
                   | (1 << OFPAT_SET_MPLS_TTL)    \
                   | (1 << OFPAT_DEC_MPLS_TTL)    \
                   | (1 << OFPAT_PUSH_VLAN)       \
                   | (1 << OFPAT_POP_VLAN)        \
                   | (1 << OFPAT_PUSH_MPLS)       \
                   | (1 << OFPAT_POP_MPLS)        \
                   | (1 << OFPAT_SET_QUEUE)       \
                   | (1 << OFPAT_GROUP)           \
                   | (1 << OFPAT_SET_NW_TTL)      \
                   | (1 << OFPAT_DEC_NW_TTL) )

#define DP_WILDCARDS    OFPFW_ALL

#define DP_MATCH_FIELDS ( OFPFMF_IN_PORT        \
                        | OFPFMF_DL_VLAN        \
                        | OFPFMF_DL_VLAN_PCP    \
                        | OFPFMF_DL_TYPE        \
                        | OFPFMF_NW_TOS         \
                        | OFPFMF_NW_PROTO       \
                        | OFPFMF_TP_SRC         \
                        | OFPFMF_TP_DST         \
                        | OFPFMF_MPLS_LABEL     \
                        | OFPFMF_MPLS_TC        \
                        | OFPFMF_TYPE           \
                        | OFPFMF_DL_SRC         \
                        | OFPFMF_DL_DST         \
                        | OFPFMF_NW_SRC         \
                        | OFPFMF_NW_SRC         \
                        | OFPFMF_NW_DST         \
                        | OFPFMF_METADATA )


#endif /* CAPABILITIES_H */
