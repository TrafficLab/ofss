/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#include <stddef.h>
#include <netinet/in.h>
#include <openflow/openflow.h>
#include "logger/logger.h"
#include "lib/compiler.h"
#include "lib/openflow.h"
#include "lib/packets.h"
#include "lib/pkt_buf.h"
#include "oflib/ofl.h"
#include "oflib/ofl_actions.h"
#include "action.h"
#include "dp_int.h"
#include "pipeline_packet.h"
#include "group_table.h"

static uint16_t
recalc_csum16(uint16_t old_csum, uint16_t old_u16, uint16_t new_u16);

static uint16_t
recalc_csum32(uint16_t old_csum, uint32_t old_u32, uint32_t new_u32);

/* Executes a set vlan vid action. */
static void
set_vlan_vid(struct pl_pkt *pl_pkt, struct ofl_action_vlan_vid *act) {
    //vlan is always the second in stack
    if ((pl_pkt->stack_depth >= 2) && ((*(pl_pkt->stack))[1].protocol == PROTO_VLAN)) {
        struct vlan_header *vlan = (struct vlan_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[1].offset);

        vlan->vlan_tci = htons((ntohs(vlan->vlan_tci) & ~VLAN_VID_MASK) | (ntohs(act->vlan_vid) & VLAN_VID_MASK));
    } else {
        logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute SET_VLAN_VID action on packet with no vlan.");
    }
}

/* Executes set vlan pcp action. */
static void
set_vlan_pcp(struct pl_pkt *pl_pkt, struct ofl_action_vlan_pcp *act) {
    //vlan is always the second in stack
    if ((pl_pkt->stack_depth >= 2) && ((*(pl_pkt->stack))[1].protocol == PROTO_VLAN)) {
        struct vlan_header *vlan = (struct vlan_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[1].offset);

        vlan->vlan_tci = htons((ntohs(vlan->vlan_tci) & ~VLAN_PCP_MASK) | ((act->vlan_pcp << VLAN_PCP_SHIFT) & VLAN_PCP_MASK));
    } else {
        logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute SET_VLAN_PCP action on packet with no vlan.");
    }
}

/* Executes set dl src action. */
static void
set_dl_src(struct pl_pkt *pl_pkt, struct ofl_action_dl_addr *act) {
    //eth is always the first in stack
    if ((pl_pkt->stack_depth >= 1) && ((*(pl_pkt->stack))[0].protocol == PROTO_ETH)) {
        struct eth_header *eth = (struct eth_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[0].offset);

        memcpy(eth->eth_src, act->dl_addr, ETH_ADDR_LEN);
    } else {
        logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute SET_DL_SRC action on packet with no dl.");
    }
}

/* Executes set dl dst action. */
static void
set_dl_dst(struct pl_pkt *pl_pkt, struct ofl_action_dl_addr *act) {
    //eth is always the first in stack
    if ((pl_pkt->stack_depth >= 1) && ((*(pl_pkt->stack))[0].protocol == PROTO_ETH)) {
        struct eth_header *eth = (struct eth_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[0].offset);

        memcpy(eth->eth_dst, act->dl_addr, ETH_ADDR_LEN);
    } else {
        logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute SET_DL_DST action on packet with no dl.");
    }
}

/* Executes set nw src action. */
static void
set_nw_src(struct pl_pkt *pl_pkt, struct ofl_action_nw_addr *act) {
    ssize_t ipv4_idx = proto_stack_indexof(pl_pkt->stack, pl_pkt->stack_depth, PROTO_IPV4);

    if (ipv4_idx >= 0) {
        struct ipv4_header *ipv4 = (struct ipv4_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[ipv4_idx].offset);

        // update TCP/UDP checksum
        if (((ssize_t)pl_pkt->stack_depth) >= ipv4_idx) {
            if ((*(pl_pkt->stack))[ipv4_idx + 1].protocol == PROTO_TCP) {
                struct tcp_header *tcp = (struct tcp_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[ipv4_idx + 1].offset);
                tcp->tcp_csum = recalc_csum32(tcp->tcp_csum, ipv4->ip_src, act->nw_addr);

            } else if ((*(pl_pkt->stack))[ipv4_idx + 1].protocol == PROTO_UDP) {
                struct udp_header *udp = (struct udp_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[ipv4_idx + 1].offset);
                udp->udp_csum = recalc_csum32(udp->udp_csum, ipv4->ip_src, act->nw_addr);
            }
        }

        ipv4->ip_csum = recalc_csum32(ipv4->ip_csum, ipv4->ip_src, act->nw_addr);
        ipv4->ip_src = act->nw_addr;
    } else {
        logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute SET_NW_SRC action on packet with no nw.");
    }
}

/* Executes set nw dst action. */
static void
set_nw_dst(struct pl_pkt *pl_pkt, struct ofl_action_nw_addr *act) {
    ssize_t ipv4_idx = proto_stack_indexof(pl_pkt->stack, pl_pkt->stack_depth, PROTO_IPV4);

    if (ipv4_idx >= 0) {
        struct ipv4_header *ipv4 = (struct ipv4_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[ipv4_idx].offset);

        // update TCP/UDP checksum
        if (((ssize_t)pl_pkt->stack_depth) >= ipv4_idx) {
            if ((*(pl_pkt->stack))[ipv4_idx + 1].protocol == PROTO_TCP) {
                struct tcp_header *tcp = (struct tcp_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[ipv4_idx + 1].offset);
                tcp->tcp_csum = recalc_csum32(tcp->tcp_csum, ipv4->ip_dst, act->nw_addr);

            } else if ((*(pl_pkt->stack))[ipv4_idx + 1].protocol == PROTO_UDP) {
                struct udp_header *udp = (struct udp_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[ipv4_idx + 1].offset);
                udp->udp_csum = recalc_csum32(udp->udp_csum, ipv4->ip_dst, act->nw_addr);
            }
        }

        ipv4->ip_csum = recalc_csum32(ipv4->ip_csum, ipv4->ip_dst, act->nw_addr);
        ipv4->ip_dst = act->nw_addr;
    } else {
        logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute SET_NW_SRC action on packet with no nw.");
    }
}

/* Executes set tp src action. */
static void
set_tp_src(struct pl_pkt *pl_pkt, struct ofl_action_tp_port *act) {
    ssize_t trans_idx = proto_stack_indexof_arr(pl_pkt->stack, pl_pkt->stack_depth, &(enum protocol[]){PROTO_TCP, PROTO_UDP}, 2);
    if (trans_idx >= 0) {
        if ((*(pl_pkt->stack))[trans_idx].protocol == PROTO_TCP) {
            struct tcp_header *tcp = (struct tcp_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[trans_idx].offset);
            tcp->tcp_csum = recalc_csum16(tcp->tcp_csum, tcp->tcp_src, act->tp_port);
            tcp->tcp_src = act->tp_port;

        } else {
            struct udp_header *udp = (struct udp_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[trans_idx].offset);
            udp->udp_csum = recalc_csum16(udp->udp_csum, udp->udp_src, act->tp_port);
            udp->udp_src = act->tp_port;
        }
    } else {
        logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute SET_TP_SRC action on packet with no tp.");
    }
}


/* Executes set tp dst action. */
static void
set_tp_dst(struct pl_pkt *pl_pkt, struct ofl_action_tp_port *act) {
    ssize_t trans_idx = proto_stack_indexof_arr(pl_pkt->stack, pl_pkt->stack_depth, &(enum protocol[]){PROTO_TCP, PROTO_UDP}, 2);
    if (trans_idx >= 0) {
        if ((*(pl_pkt->stack))[trans_idx].protocol == PROTO_TCP) {
            struct tcp_header *tcp = (struct tcp_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[trans_idx].offset);
            tcp->tcp_csum = recalc_csum16(tcp->tcp_csum, tcp->tcp_dst, act->tp_port);
            tcp->tcp_dst = act->tp_port;

        } else {
            struct udp_header *udp = (struct udp_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[trans_idx].offset);
            udp->udp_csum = recalc_csum16(udp->udp_csum, udp->udp_dst, act->tp_port);
            udp->udp_dst = act->tp_port;
        }
    } else {
        logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute SET_TP_DST action on packet with no tp.");
    }
}

/* Executes copy ttl out action. */
static void
copy_ttl_out(struct pl_pkt *pl_pkt, struct ofl_action_header *act UNUSED_ATTR) {
    // currently ttl is only copied out to mpls from another mpls or ipv4 header
    ssize_t mpls_idx = proto_stack_indexof(pl_pkt->stack, pl_pkt->stack_depth, PROTO_MPLS);

    if (mpls_idx >= 0 && ((ssize_t)pl_pkt->stack_depth) >= mpls_idx) { // there is more protocol behind
        if ((*pl_pkt->stack)[mpls_idx+1].protocol == PROTO_MPLS) {
            struct mpls_header *mpls_out = (struct mpls_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[mpls_idx].offset);
            struct mpls_header *mpls_in = (struct mpls_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[mpls_idx+1].offset);

            mpls_out->fields = (mpls_out->fields & ~htonl(MPLS_TTL_MASK)) | (mpls_in->fields & htonl(MPLS_TTL_MASK));

        } else if ((*pl_pkt->stack)[mpls_idx+1].protocol == PROTO_IPV4) {
            struct mpls_header *mpls_out = (struct mpls_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[mpls_idx].offset);
            struct ipv4_header *ipv4_in = (struct ipv4_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[mpls_idx+1].offset);

            mpls_out->fields = (mpls_out->fields & ~htonl(MPLS_TTL_MASK)) | htonl((uint32_t)(ipv4_in->ip_ttl) & MPLS_TTL_MASK);
        } else {
            logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute copy ttl in action on packet with only one mpls and no ipv4.");
        }
    } else {
        logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute COPY_TTL_OUT action on packet with no mpls.");
    }
}

/* Executes copy ttl in action. */
static void
copy_ttl_in(struct pl_pkt *pl_pkt, struct ofl_action_header *act UNUSED_ATTR) {
    // currently ttl is only copied in from mpls to another mpls or ipv4 header
    ssize_t mpls_idx = proto_stack_indexof(pl_pkt->stack, pl_pkt->stack_depth, PROTO_MPLS);

    if (mpls_idx >= 0 && ((ssize_t)pl_pkt->stack_depth) >= mpls_idx) { // there is at least one more protocol behind
        if ((*pl_pkt->stack)[mpls_idx+1].protocol == PROTO_MPLS) {
            struct mpls_header *mpls_out = (struct mpls_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[mpls_idx].offset);
            struct mpls_header *mpls_in = (struct mpls_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[mpls_idx+1].offset);

            mpls_in->fields = (mpls_in->fields & ~htonl(MPLS_TTL_MASK)) | (mpls_out->fields & htonl(MPLS_TTL_MASK));

        } else if ((*pl_pkt->stack)[mpls_idx+1].protocol == PROTO_IPV4) {
            struct mpls_header *mpls_out = (struct mpls_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[mpls_idx].offset);
            struct ipv4_header *ipv4_in = (struct ipv4_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[mpls_idx+1].offset);

            uint16_t old_val = htons((ipv4_in->ip_proto) + (ipv4_in->ip_ttl<<8));
            uint16_t new_val = htons((ipv4_in->ip_proto) + (((ntohl(mpls_out->fields) & MPLS_TTL_MASK) >> MPLS_TTL_SHIFT)<<8));

            ipv4_in->ip_csum = recalc_csum16(ipv4_in->ip_csum, old_val, new_val);
            ipv4_in->ip_ttl = ((ntohl(mpls_out->fields) & MPLS_TTL_MASK) >> MPLS_TTL_SHIFT);
        } else {
            logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute copy ttl in action on packet with only one mpls and no ipv4.");
        }
    } else {
        logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute COPY_TTL_IN action on packet with no mpls.");
    }
}

/* Executes set mpls label action. */
static void
set_mpls_label(struct pl_pkt *pl_pkt, struct ofl_action_mpls_label *act) {
    ssize_t mpls_idx = proto_stack_indexof(pl_pkt->stack, pl_pkt->stack_depth, PROTO_MPLS);

    if (mpls_idx >= 0) {
        struct mpls_header *mpls = (struct mpls_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[mpls_idx].offset);

        mpls->fields = htonl((ntohl(mpls->fields) & ~MPLS_LABEL_MASK) | ((ntohl(act->mpls_label) << MPLS_LABEL_SHIFT) & MPLS_LABEL_MASK));
    } else {
        logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute SET_MPLS_LABEL action on packet with no mpls.");
    }
}

/* Executes set mpls tc action. */
static void
set_mpls_tc(struct pl_pkt *pl_pkt, struct ofl_action_mpls_tc *act) {
    ssize_t mpls_idx = proto_stack_indexof(pl_pkt->stack, pl_pkt->stack_depth, PROTO_MPLS);

    if (mpls_idx >= 0) {
        struct mpls_header *mpls = (struct mpls_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[mpls_idx].offset);

        mpls->fields = htonl((ntohl(mpls->fields) & ~MPLS_TC_MASK) | ((act->mpls_tc << MPLS_TC_SHIFT) & MPLS_TC_MASK));

    } else {
        logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute SET_MPLS_TC action on packet with no mpls.");
    }
}

/* Executes set nw tos action. */
static void
set_nw_tos(struct pl_pkt *pl_pkt, struct ofl_action_nw_tos *act) {
    ssize_t ipv4_idx = proto_stack_indexof(pl_pkt->stack, pl_pkt->stack_depth, PROTO_IPV4);

    if (ipv4_idx >= 0) {
        struct ipv4_header *ipv4 = (struct ipv4_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[ipv4_idx].offset);
        uint8_t new_tos = (ipv4->ip_tos & IP_ECN_MASK) | (act->nw_tos & IP_DSCP_MASK);

        uint16_t old_value = (ipv4->ip_tos << 8) + ipv4->ip_ihl_ver;
        uint16_t new_value = (new_tos << 8) + ipv4->ip_ihl_ver;

        ipv4->ip_csum = recalc_csum16(ipv4->ip_csum, old_value, new_value);
        ipv4->ip_tos = new_tos;
    } else {
        logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute SET_NW_TOS action on packet with no tp.");
    }
}

/* Executes set nw ecn action. */
static void
set_nw_ecn(struct pl_pkt *pl_pkt, struct ofl_action_nw_ecn *act) {
    ssize_t ipv4_idx = proto_stack_indexof(pl_pkt->stack, pl_pkt->stack_depth, PROTO_IPV4);

    if (ipv4_idx >= 0) {
        struct ipv4_header *ipv4 = (struct ipv4_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[ipv4_idx].offset);
        uint8_t new_tos = (ipv4->ip_tos & IP_DSCP_MASK) | (act->nw_ecn & IP_ECN_MASK);

        uint16_t old_value = (ipv4->ip_tos << 8) + ipv4->ip_ihl_ver;
        uint16_t new_value = (new_tos << 8) + ipv4->ip_ihl_ver;

        ipv4->ip_csum = recalc_csum16(ipv4->ip_csum, old_value, new_value);
        ipv4->ip_tos = new_tos;
    } else {
        logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute SET_NW_ECN action on packet with no tp.");
    }
}

/* Executes push vlan action. */
static void
push_vlan(struct pl_pkt *pl_pkt, struct ofl_action_push *act) {
    // TODO check if new length is still valid for 802.3
    // vlan is always pushed to idx 1
    if ((((ssize_t)pl_pkt->stack_depth) >= 1) && ((*(pl_pkt->stack))[0].protocol == PROTO_ETH)) {

        struct pkt_buf *pkt = pl_pkt->pkt;

        pkt_buf_ensure_headroom(pkt, sizeof(struct vlan_header));

        pkt->data -= sizeof(struct vlan_header);
        pkt->data_len += sizeof(struct vlan_header);

        //make place for vlan
        memmove(pkt->data, pkt->data + sizeof(struct vlan_header), (*(pl_pkt->stack))[0].length);

        struct vlan_header *new_vlan = (struct vlan_header *)(pkt->data + (*(pl_pkt->stack))[0].offset + (*(pl_pkt->stack))[0].length);
        pl_pkt->std_protos.vlan = new_vlan;
        //std_protos.dl_type does not change
        memset(new_vlan, 0, sizeof(struct vlan_header));
        proto_stack_push(&(pl_pkt->stack), &(pl_pkt->stack_depth), &(pl_pkt->stack_size),
                         1, PROTO_VLAN, PROTO_TYPE_OK, sizeof(struct vlan_header));

        struct eth_header *eth = (struct eth_header *)(pkt->data + (*(pl_pkt->stack))[0].offset);
        pl_pkt->std_protos.eth = eth;

        if ((*(pl_pkt->stack))[0].type == PROTO_TYPE_ETH_SNAP) {
            struct snap_header *snap = (struct snap_header *)(pkt->data + (*(pl_pkt->stack))[0].offset + sizeof(struct eth_header) + sizeof(struct llc_header));
            new_vlan->vlan_next_type = snap->snap_type;
            eth->eth_type += htons(ntohs(eth->eth_type) + sizeof(struct vlan_header));
            snap->snap_type = act->ethertype;
        } else {
            new_vlan->vlan_next_type = eth->eth_type;
            eth->eth_type = act->ethertype;
        }

        if (pl_pkt->stack_depth >= 2 && (*(pl_pkt->stack))[2].protocol == PROTO_VLAN) {
            // copy tci from other vlan
            struct vlan_header *old_vlan = (struct vlan_header *)(pkt->data + (*(pl_pkt->stack))[1].offset + sizeof(struct vlan_header));
            new_vlan->vlan_tci = old_vlan->vlan_tci;
        }

    } else {
        logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute push vlan action on packet with no eth.");
    }
}

/* Executes pop vlan action. */
static void
pop_vlan(struct pl_pkt *pl_pkt, struct ofl_action_header *act UNUSED_ATTR) {
    if ((pl_pkt->stack_depth >= 2) &&
        ((*(pl_pkt->stack))[0].protocol == PROTO_ETH) &&
        ((*(pl_pkt->stack))[1].protocol == PROTO_VLAN)) {

        struct pkt_buf *pkt = pl_pkt->pkt;

        struct eth_header *eth = (struct eth_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[0].offset);
        struct vlan_header *vlan = (struct vlan_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[1].offset);

        if ((*(pl_pkt->stack))[0].type == PROTO_TYPE_ETH_SNAP) {
            struct snap_header *snap = (struct snap_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[0].offset + sizeof(struct eth_header) + sizeof(struct llc_header));
            snap->snap_type = vlan->vlan_next_type;
            eth->eth_type = htons(ntohs(eth->eth_type) - sizeof(struct vlan_header));
        } else {
            eth->eth_type = vlan->vlan_next_type;
        }

        memmove(pkt->data + sizeof(struct vlan_header), pl_pkt->pkt->data, (*(pl_pkt->stack))[0].length);

        pkt->data += sizeof(struct vlan_header);
        pkt->data_len -= sizeof(struct vlan_header);

        proto_stack_pop(pl_pkt->stack, &(pl_pkt->stack_depth), 1);

        pl_pkt->std_protos.eth = (struct eth_header *)(pkt->data + (*(pl_pkt->stack))[0].offset);

        // is there still a vlan tag?
        if (pl_pkt->stack_depth >= 2 && (*(pl_pkt->stack))[1].protocol == PROTO_VLAN) {
            pl_pkt->std_protos.vlan = (struct vlan_header *)(pkt->data + (*(pl_pkt->stack))[1].offset);
        } else {
            pl_pkt->std_protos.vlan = NULL;
        }
        //std_protos.dl_type does not change
    } else {
        logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute POP_VLAN action on packet with no eth/vlan.");
    }
}


/* Executes set mpls ttl action. */
static void
set_mpls_ttl(struct pl_pkt *pl_pkt, struct ofl_action_mpls_ttl *act) {
    ssize_t mpls_idx = proto_stack_indexof(pl_pkt->stack, pl_pkt->stack_depth, PROTO_MPLS);

    if (mpls_idx >= 0) {
        struct mpls_header *mpls = (struct mpls_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[mpls_idx].offset);

        mpls->fields = htonl((ntohl(mpls->fields) & ~MPLS_TTL_MASK) | ((act->mpls_ttl << MPLS_TTL_SHIFT) & MPLS_TTL_MASK));
    } else {
        logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute SET_MPLS_TTL action on packet with no mpls.");
    }
}

/* Executes dec mpls label action. */
static void
dec_mpls_ttl(struct pl_pkt *pl_pkt, struct ofl_action_header *act UNUSED_ATTR) {
    ssize_t mpls_idx = proto_stack_indexof(pl_pkt->stack, pl_pkt->stack_depth, PROTO_MPLS);

    if (mpls_idx >= 0) {
        struct mpls_header *mpls = (struct mpls_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[mpls_idx].offset);
        uint32_t ttl = ntohl(mpls->fields) & MPLS_TTL_MASK;
        if (ttl > 0) { ttl--; }
        mpls->fields = (mpls->fields & ~ntohl(MPLS_TTL_MASK)) | htonl(ttl);
    } else {
        logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute DEC_MPLS_TTL action on packet with no mpls.");
    }
}

/* Executes push mpls action. */
static void
push_mpls(struct pl_pkt *pl_pkt, struct ofl_action_push *act) {
    // TODO check if new length is still valid for 802.3
    ssize_t idx = proto_stack_indexof_arr_last(pl_pkt->stack, pl_pkt->stack_depth, &(enum protocol[]){PROTO_ETH, PROTO_VLAN}, 2);

    if (idx < 0) {
        logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute PUSH_MPLS action on packet with no eth.");
        return;
    }

    struct pkt_buf *pkt = pl_pkt->pkt;
    size_t move_size = (*(pl_pkt->stack))[idx].offset + (*(pl_pkt->stack))[idx].length;

    pkt_buf_ensure_headroom(pkt, sizeof(struct mpls_header));

    //make place for mpls
    memmove(pkt->data - sizeof(struct mpls_header), pkt->data, move_size);
    pkt->data -= sizeof(struct mpls_header);
    pkt->data_len += sizeof(struct mpls_header);

    //no need for memset, field is set later
    struct mpls_header *new_mpls = (struct mpls_header *)(pkt->data + move_size);

    pl_pkt->std_protos.mpls = new_mpls;
    pl_pkt->std_protos.dl_type = act->ethertype;

    // hide old layers from std match
    pl_pkt->std_protos.ipv4 = NULL;
    pl_pkt->std_protos.arp = NULL;
    pl_pkt->std_protos.tcp = NULL;
    pl_pkt->std_protos.udp = NULL;
    pl_pkt->std_protos.icmp = NULL;
    pl_pkt->std_protos.sctp = NULL;

    proto_stack_push(&(pl_pkt->stack), &(pl_pkt->stack_depth), &(pl_pkt->stack_size),
                     idx + 1, PROTO_MPLS, PROTO_TYPE_OK, sizeof(struct mpls_header));

    if ((*(pl_pkt->stack))[idx].protocol == PROTO_VLAN) {
        struct vlan_header *vlan = (struct vlan_header *)(pkt->data + (*(pl_pkt->stack))[idx].offset);
        vlan->vlan_next_type = act->ethertype;

        pl_pkt->std_protos.eth = (struct eth_header *)(pkt->data + (*(pl_pkt->stack))[0].offset);
        pl_pkt->std_protos.vlan = (struct vlan_header *)(pkt->data + (*(pl_pkt->stack))[1].offset);
    } else if ((*(pl_pkt->stack))[idx].protocol == PROTO_ETH) {
        struct eth_header *eth = (struct eth_header *)(pkt->data + (*(pl_pkt->stack))[idx].offset);

        if ((*(pl_pkt->stack))[idx].type == PROTO_TYPE_ETH_SNAP) {
            struct snap_header *snap = (struct snap_header *)(pkt->data + (*(pl_pkt->stack))[idx].offset + sizeof(struct eth_header) + sizeof(struct llc_header));
            snap->snap_type = act->ethertype;
            eth->eth_type += htons(ntohs(eth->eth_type) + sizeof(struct mpls_header));
        } else {
            eth->eth_type = act->ethertype;
        }

        pl_pkt->std_protos.eth = eth;
    }

    if (((ssize_t)pl_pkt->stack_depth) > idx + 2) {
        if ((*(pl_pkt->stack))[idx+2].protocol == PROTO_MPLS) {
            struct mpls_header *old_mpls = (struct mpls_header *)(pkt->data + (*(pl_pkt->stack))[idx+2].offset);
            new_mpls->fields = old_mpls->fields & ~htonl(MPLS_S_MASK);
        } else if ((*(pl_pkt->stack))[idx+2].protocol == PROTO_IPV4) {
            struct ipv4_header *old_ipv4 = (struct ipv4_header *)(pkt->data + (*(pl_pkt->stack))[idx+2].offset);
            new_mpls->fields = htonl(MPLS_S_MASK);
            new_mpls->fields = (new_mpls->fields & ~ntohl(MPLS_TTL_MASK)) | ntohl((old_ipv4->ip_ttl << MPLS_TTL_SHIFT) & MPLS_TTL_MASK);
        } else {
            new_mpls->fields = htonl(MPLS_S_MASK);
        }
    }

}

/* Executes pop mpls action. */
static void
pop_mpls(struct pl_pkt *pl_pkt, struct ofl_action_pop_mpls *act) {
    ssize_t mpls_idx = proto_stack_indexof(pl_pkt->stack, pl_pkt->stack_depth, PROTO_MPLS);

    if (mpls_idx > 0) { // = 0 is not OK
        struct pkt_buf *pkt = pl_pkt->pkt;

        memmove(pkt->data + sizeof(struct mpls_header), pkt->data, (*(pl_pkt->stack))[mpls_idx - 1].offset + (*(pl_pkt->stack))[mpls_idx - 1].length);
        pkt->data += sizeof(struct mpls_header);
        pkt->data_len -= sizeof(struct mpls_header);

        proto_stack_pop(pl_pkt->stack, &(pl_pkt->stack_depth), mpls_idx);
        pl_pkt->std_protos.dl_type = act->ethertype;
        if ((ssize_t)(pl_pkt->stack_depth) > mpls_idx && (*(pl_pkt->stack))[mpls_idx].protocol == PROTO_IPV4 && act->ethertype == htons(ETH_TYPE_IPV4)) {
            // if act->dl_type is IPv4 and there is indeed IPv4, set it and its transport in standard match fields
            pl_pkt->std_protos.mpls = NULL;
            pl_pkt->std_protos.ipv4 = (struct ipv4_header *)(pkt->data + (*(pl_pkt->stack))[mpls_idx].offset);
            if ((ssize_t)(pl_pkt->stack_depth) > (mpls_idx+1)) {
                if ((*(pl_pkt->stack))[mpls_idx+1].protocol == PROTO_TCP) {
                    pl_pkt->std_protos.tcp = (struct tcp_header *)(pkt->data + (*(pl_pkt->stack))[mpls_idx+1].offset);
                } else if ((*(pl_pkt->stack))[mpls_idx+1].protocol == PROTO_UDP) {
                        pl_pkt->std_protos.udp = (struct udp_header *)(pkt->data + (*(pl_pkt->stack))[mpls_idx+1].offset);
                } else if ((*(pl_pkt->stack))[mpls_idx+1].protocol == PROTO_SCTP) {
                        pl_pkt->std_protos.sctp = (struct sctp_header *)(pkt->data + (*(pl_pkt->stack))[mpls_idx+1].offset);
                } else if ((*(pl_pkt->stack))[mpls_idx+1].protocol == PROTO_UDP) {
                        pl_pkt->std_protos.icmp = (struct icmp_header *)(pkt->data + (*(pl_pkt->stack))[mpls_idx+1].offset);
                }
            }
        } else if ((ssize_t)(pl_pkt->stack_depth) > mpls_idx && (*(pl_pkt->stack))[mpls_idx].protocol == PROTO_MPLS &&
                   ((act->ethertype == htons(ETH_TYPE_MPLS)) || (act->ethertype == htons(ETH_TYPE_MPLS_MCAST)))) {
            // if act->dl_type is for MPLS, and there was MPLS, keep everything as is
            pl_pkt->std_protos.mpls = (struct mpls_header *)(pkt->data + (*(pl_pkt->stack))[mpls_idx].offset);

        } else {
            // otherwise invalidate packet parsing by setting the rest of the packet to payload
            pl_pkt->stack_depth = mpls_idx+1;
            (*(pl_pkt->stack))[mpls_idx] = (struct stack_entry){.protocol = PROTO_PAYLOAD, .type = PROTO_TYPE_OK,
                                                                .offset = (*(pl_pkt->stack))[mpls_idx-1].offset + (*(pl_pkt->stack))[mpls_idx-1].length,
                                                                .length = pkt->data_len - (*(pl_pkt->stack))[mpls_idx-1].offset - (*(pl_pkt->stack))[mpls_idx-1].length};
        }

        if ((*(pl_pkt->stack))[mpls_idx - 1].protocol == PROTO_VLAN) {
            struct vlan_header *vlan = (struct vlan_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[mpls_idx - 1].offset);
            vlan->vlan_next_type = act->ethertype;

            pl_pkt->std_protos.eth = (struct eth_header *)(pkt->data + (*(pl_pkt->stack))[0].offset);
            pl_pkt->std_protos.vlan = (struct vlan_header *)(pkt->data + (*(pl_pkt->stack))[1].offset);
        } else if ((*(pl_pkt->stack))[mpls_idx - 1].protocol == PROTO_ETH) {
            struct eth_header *eth = (struct eth_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[mpls_idx - 1].offset);
            if ((*(pl_pkt->stack))[mpls_idx - 1].type == PROTO_TYPE_ETH_SNAP) {
                struct snap_header *eth_snap = (struct snap_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[mpls_idx - 1].offset +  + sizeof(struct eth_header) + sizeof(struct llc_header));
                eth_snap->snap_type = act->ethertype;
                eth->eth_type = htons(ntohs(eth->eth_type) - sizeof(struct mpls_header));
            } else {
                eth->eth_type = act->ethertype;
            }

            pl_pkt->std_protos.eth = eth;
        }
    } else {
        logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute POP_MPLS action on packet with no eth/mpls.");
    }
}


/* Executes set nw ttl action. */
static void
set_nw_ttl(struct pl_pkt *pl_pkt, struct ofl_action_set_nw_ttl *act) {
    ssize_t ipv4_idx = proto_stack_indexof(pl_pkt->stack, pl_pkt->stack_depth, PROTO_IPV4);

    if (ipv4_idx >= 0) {
        struct ipv4_header *ipv4 = (struct ipv4_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[ipv4_idx].offset);
        uint16_t old_val = htons((ipv4->ip_proto) + (ipv4->ip_ttl<<8));
        uint16_t new_val = htons((ipv4->ip_proto) + (act->nw_ttl<<8));
        ipv4->ip_csum = recalc_csum16(ipv4->ip_csum, old_val, new_val);
        ipv4->ip_ttl = act->nw_ttl;
    } else {
        logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute SET_NW_TTL action on packet with no ipv4.");
    }
}

/* Executes dec nw ttl action. */
static void
dec_nw_ttl(struct pl_pkt *pl_pkt, struct ofl_action_header *act UNUSED_ATTR) {
    ssize_t ipv4_idx = proto_stack_indexof(pl_pkt->stack, pl_pkt->stack_depth, PROTO_IPV4);

    if (ipv4_idx >= 0) {
        struct ipv4_header *ipv4 = (struct ipv4_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[ipv4_idx].offset);
        if (ipv4->ip_ttl > 0) {
            uint8_t new_ttl = ipv4->ip_ttl - 1;
            uint16_t old_val = htons((ipv4->ip_proto) + (ipv4->ip_ttl<<8));
            uint16_t new_val = htons((ipv4->ip_proto) + (new_ttl<<8));
            ipv4->ip_csum = recalc_csum16(ipv4->ip_csum, old_val, new_val);
            ipv4->ip_ttl = new_ttl;
        }
    } else {
        logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute DEC_NW_TTL action on packet with no ipv4.");
    }
}

/* Executes an action on the packet.
 * Returns an act_res structure if something needs to be done
 * with the packet.
 */
struct act_res
action_exec(struct pl_pkt *pl_pkt, struct ofl_action_header *action) {
    if (logger_is_enabled(pl_pkt->logger, LOG_DEBUG)) {
        char *a = ofl_action_to_string(action, OFL_NO_EXP);
        logger_log(pl_pkt->logger, LOG_DEBUG, "executing action %s.", a);
        free(a);
    }

    switch (action->type) {
        case (OFPAT_OUTPUT): {
            struct ofl_action_output *ao = (struct ofl_action_output *)action;
            return (struct act_res){.type = DP_ACT_PORT, .port = {.port_id = ao->port, .max_len = ao->max_len}};
        }
        case (OFPAT_SET_VLAN_VID): {
            set_vlan_vid(pl_pkt, (struct ofl_action_vlan_vid *)action);
            break;
        }
        case (OFPAT_SET_VLAN_PCP): {
            set_vlan_pcp(pl_pkt, (struct ofl_action_vlan_pcp *)action);
            break;
        }
        case (OFPAT_SET_DL_SRC): {
            set_dl_src(pl_pkt, (struct ofl_action_dl_addr *)action);
            break;
        }
        case (OFPAT_SET_DL_DST): {
            set_dl_dst(pl_pkt, (struct ofl_action_dl_addr *)action);
            break;
        }
        case (OFPAT_SET_NW_SRC): {
            set_nw_src(pl_pkt, (struct ofl_action_nw_addr *)action);
            break;
        }
        case (OFPAT_SET_NW_DST): {
            set_nw_dst(pl_pkt, (struct ofl_action_nw_addr *)action);
            break;
        }
        case (OFPAT_SET_NW_TOS): {
            set_nw_tos(pl_pkt, (struct ofl_action_nw_tos *)action);
            break;
        }
        case (OFPAT_SET_NW_ECN): {
            set_nw_ecn(pl_pkt, (struct ofl_action_nw_ecn *)action);
            break;
        }
        case (OFPAT_SET_TP_SRC): {
            set_tp_src(pl_pkt, (struct ofl_action_tp_port *)action);
            break;
        }
        case (OFPAT_SET_TP_DST): {
            set_tp_dst(pl_pkt, (struct ofl_action_tp_port *)action);
            break;
        }
        case (OFPAT_COPY_TTL_OUT): {
            copy_ttl_out(pl_pkt, action);
            break;
        }
        case (OFPAT_COPY_TTL_IN): {
            copy_ttl_in(pl_pkt, action);
            break;
        }
        case (OFPAT_SET_MPLS_LABEL): {
            set_mpls_label(pl_pkt, (struct ofl_action_mpls_label *)action);
            break;
        }
        case (OFPAT_SET_MPLS_TC): {
            set_mpls_tc(pl_pkt, (struct ofl_action_mpls_tc *)action);
            break;
        }
        case (OFPAT_SET_MPLS_TTL): {
            set_mpls_ttl(pl_pkt, (struct ofl_action_mpls_ttl *)action);
            break;
        }
        case (OFPAT_DEC_MPLS_TTL): {
            dec_mpls_ttl(pl_pkt, action);
            break;
        }
        case (OFPAT_PUSH_VLAN): {
            push_vlan(pl_pkt, (struct ofl_action_push *)action);
            break;
        }
        case (OFPAT_POP_VLAN): {
            pop_vlan(pl_pkt, action);
            break;
        }
        case (OFPAT_PUSH_MPLS): {
            push_mpls(pl_pkt, (struct ofl_action_push *)action);
            break;
        }
        case (OFPAT_POP_MPLS): {
            pop_mpls(pl_pkt, (struct ofl_action_pop_mpls *)action);
            break;
        }
        case (OFPAT_SET_QUEUE): {
            struct ofl_action_set_queue *aq = (struct ofl_action_set_queue *)action;
            pl_pkt->queue = aq->queue_id;
            break;

        }
        case (OFPAT_GROUP): {
            struct ofl_action_group *ag = (struct ofl_action_group *)action;
            return (struct act_res){.type = DP_ACT_GROUP, .group_id = ag->group_id};
        }
        case (OFPAT_SET_NW_TTL): {
            set_nw_ttl(pl_pkt, (struct ofl_action_set_nw_ttl *)action);
            break;
        }
        case (OFPAT_DEC_NW_TTL): {
            dec_nw_ttl(pl_pkt, action);
            break;
        }
        case (OFPAT_EXPERIMENTER): {
            logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute experimenter action.");
            break;
        }
        default: {
            logger_log(pl_pkt->logger, LOG_WARN, "Trying to execute unknown action type (%u).", action->type);
            break;
        }
    }
    if (logger_is_enabled(pl_pkt->logger, LOG_DEBUG)) {
        char *p = pl_pkt_to_string(pl_pkt);
        logger_log(pl_pkt->logger, LOG_DEBUG, "Action result:\n%s", p);
        free(p);
    }
    return (struct act_res){.type = DP_ACT_NONE};
}


/* Validates an action. */
ofl_err
action_validate(struct dp_loop *dp_loop, struct ofl_action_header *act) {
    switch (act->type) {
        case OFPAT_OUTPUT: {
            struct ofl_action_output *ao = (struct ofl_action_output *)act;

            if (ao->port <= OFPP_MAX) {
                pthread_rwlock_rdlock(dp_loop->dp->ports_lock);
                if (dp_loop->dp->ports[ao->port] == NULL) {
                    logger_log(dp_loop->logger_pl, LOG_DEBUG, "Output action for invalid port (%u).", ao->port);
                    pthread_rwlock_unlock(dp_loop->dp->ports_lock);
                    return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT);
                }
                pthread_rwlock_rdlock(dp_loop->dp->ports_lock);
            }
            return 0;
        }
        case OFPAT_GROUP: {
            struct ofl_action_group *ag = (struct ofl_action_group *)act;

            if ((ag->group_id <= OFPG_MAX) && !group_table_has(dp_loop->groups, ag->group_id)) {
                logger_log(dp_loop->logger_pl, LOG_DEBUG, "Group action for invalid group (%u).", ag->group_id);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_GROUP);
            }
            return 0;
        }
        default: {
            return 0;
        }
    }
}



/* Returns the new checksum for a packet. */
static CONST_ATTR uint16_t
recalc_csum16(uint16_t old_csum, uint16_t old_u16, uint16_t new_u16) {
    /* Ones-complement arithmetic is endian-independent, so this code does not
     * use htons() or ntohs().
     *
     * See RFC 1624 for formula and explanation. */
    uint16_t hc_complement = ~old_csum;
    uint16_t m_complement = ~old_u16;
    uint16_t m_prime = new_u16;
    uint32_t sum = hc_complement + m_complement + m_prime;
    uint16_t hc_prime_complement = sum + (sum >> 16);
    return ~hc_prime_complement;
}

/* Returns the new checksum for a packet. */
static CONST_ATTR uint16_t
recalc_csum32(uint16_t old_csum, uint32_t old_u32, uint32_t new_u32) {
    return recalc_csum16(recalc_csum16(old_csum, old_u32, new_u32),
                         old_u32 >> 16, new_u32 >> 16);
}
