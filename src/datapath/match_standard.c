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
 * Provides standard match related functions.
 */
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include "lib/compiler.h"
#include "lib/packets.h"
#include "lib/pkt_buf.h"
#include "logger/logger.h"
#include "match_standard.h"
#include "pipeline_packet.h"
#include "oflib/ofl_structs.h"

/* bug caused by openflow.h */
#undef icmp_type
#undef icmp_code

/* Returns true if the given field is set in the wildcard field */
static inline bool CONST_ATTR
wc(uint32_t wildcards, uint32_t field) {
    return ((wildcards & field) != 0);
}

/* Two matches overlap, if there exists a packet,
   which both match structures match on. */
bool
match_std_overlap(struct ofl_match_standard *a, struct ofl_match_standard *b) {
    return match_std_nonstrict(a, b) || match_std_nonstrict(b, a);
}

/* Two matches strictly match, if their wildcard fields are the same, and all the
 * non-wildcarded fields match on the same exact values.
 * NOTE: Handling of bitmasked fields is not specified. In this implementation
 * masked fields are checked for equality, and only unmasked bits are compared
 * in the field.
 */
static inline bool CONST_ATTR
strict_wild8(uint8_t a, uint8_t b, uint32_t aw, uint32_t bw, uint32_t f) {
    return (wc(aw, f) && wc(bw, f)) ||
          (~wc(aw, f) && ~wc(bw, f) && a == b);
}

static inline bool CONST_ATTR
strict_wild16(uint16_t a, uint16_t b, uint32_t aw, uint32_t bw, uint32_t f) {
    return (wc(aw, f) && wc(bw, f)) ||
          (~wc(aw, f) && ~wc(bw, f) && a == b);
}

static inline bool CONST_ATTR
strict_wild32(uint32_t a, uint32_t b, uint32_t aw, uint32_t bw, uint32_t f) {
    return (wc(aw, f) && wc(bw, f)) ||
          (~wc(aw, f) && ~wc(bw, f) && a == b);
}

static inline bool CONST_ATTR
strict_mask16(uint16_t a, uint16_t b, uint16_t am, uint16_t bm) {
    return (am == bm) && ((a ^ b) & ~am) == 0;
}

static inline bool CONST_ATTR
strict_mask32(uint32_t a, uint32_t b, uint32_t am, uint32_t bm) {
    return (am == bm) && ((a ^ b) & ~am) == 0;
}

static inline bool CONST_ATTR
strict_mask64(uint64_t a, uint64_t b, uint64_t am, uint64_t bm) {
    return (am == bm) && ((a ^ b) & ~am) == 0;
}

static inline bool
strict_dladdr(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
    return strict_mask32(*((uint32_t *)a), *((uint32_t *)b), *((uint32_t *)am), *((uint32_t *)bm)) &&
           strict_mask16(*((uint16_t *)(a+4)), *((uint16_t *)(b+4)), *((uint16_t *)(am+4)), *((uint16_t *)(bm+4)));}


/* Tells whether the two match structures match (strict). */
bool
match_std_strict(struct ofl_match_standard *a, struct ofl_match_standard *b) {
    return strict_wild32(a->in_port, b->in_port, a->wildcards, b->wildcards, OFPFW_IN_PORT) &&
           strict_dladdr(a->dl_src, b->dl_src, a->dl_src_mask, b->dl_src_mask) &&
           strict_dladdr(a->dl_dst, b->dl_dst, a->dl_dst_mask, b->dl_dst_mask) &&
           strict_wild16(a->dl_vlan, b->dl_vlan, a->wildcards, b->wildcards, OFPFW_DL_VLAN) &&
           strict_wild16(a->dl_vlan_pcp, b->dl_vlan_pcp, a->wildcards, b->wildcards, OFPFW_DL_VLAN_PCP) &&
           strict_wild16(a->dl_type, b->dl_type, a->wildcards, b->wildcards, OFPFW_DL_TYPE) &&
           strict_wild8 (a->nw_tos, b->nw_tos, a->wildcards, b->wildcards, OFPFW_NW_TOS) &&
           strict_wild8 (a->nw_proto, b->nw_proto, a->wildcards, b->wildcards, OFPFW_NW_PROTO) &&
           strict_mask32(a->nw_src, b->nw_src, a->nw_src_mask, b->nw_src_mask) &&
           strict_mask32(a->nw_dst, b->nw_dst, a->nw_dst_mask, b->nw_dst_mask) &&
           strict_wild16(a->tp_src, b->tp_src, a->wildcards, b->wildcards, OFPFW_TP_SRC) &&
           strict_wild16(a->tp_dst, b->tp_dst, a->wildcards, b->wildcards, OFPFW_TP_DST) &&
           strict_wild32(a->mpls_label, b->mpls_label, a->wildcards, b->wildcards, OFPFW_MPLS_LABEL) &&
           strict_wild8 (a->mpls_tc, b->mpls_tc, a->wildcards, b->wildcards, OFPFW_MPLS_TC) &&
           strict_mask64(a->metadata, b->metadata, a->metadata_mask, b->metadata_mask);
}


/* A match (a) non-strictly matches match (b), if for each field they are both
 * wildcarded, or (a) is wildcarded, and (b) isn't, or if neither is wildcarded
 * and they match on the same value.
 * NOTE: Handling of bitmasked fields is not specified. In this implementation
 * a masked field of (a) matches the field of (b) if all masked bits of (b) are
 * also masked in (a), and for each unmasked bits of (b) , the bit is either
 * masked in (a), or is set to the same value in both matches.
 * NOTE: This function is also used for flow matching on packets, where in packets
 * all wildcards and masked fields are set to zero.
 */
static inline bool CONST_ATTR
nonstrict_wild8(uint8_t a, uint8_t b, uint32_t aw, uint32_t bw, uint32_t f) {
    return (wc(bw, f) && wc(aw, f)) ||
          (~wc(bw, f) && (wc(aw, f) || a == b));
}

static inline bool CONST_ATTR
nonstrict_wild16(uint16_t a, uint16_t b, uint32_t aw, uint32_t bw, uint32_t f) {
    return (wc(bw, f) && wc(aw, f)) ||
          (~wc(bw, f) && (wc(aw, f) || a == b));
}

static inline bool CONST_ATTR
nonstrict_wild32(uint32_t a, uint32_t b, uint32_t aw, uint32_t bw, uint32_t f) {
    return (wc(bw, f) && wc(aw, f)) ||
          (~wc(bw, f) && (wc(aw, f) || a == b));
}

static inline bool CONST_ATTR
nonstrict_mask16(uint16_t a, uint16_t b, uint16_t am, uint16_t bm) {
    return (~am & (~a | ~b | bm) & (a | b | bm)) == 0;
}

static inline bool CONST_ATTR
nonstrict_mask32(uint32_t a, uint32_t b, uint32_t am, uint32_t bm) {
    return (~am & (~a | ~b | bm) & (a | b | bm)) == 0;
}

static inline bool CONST_ATTR
nonstrict_mask64(uint64_t a, uint64_t b, uint64_t am, uint64_t bm) {
    return (~am & (~a | ~b | bm) & (a | b | bm)) == 0;
}

static inline bool
nonstrict_dladdr(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
    return nonstrict_mask32(*((uint32_t *)a), *((uint32_t *)b), *((uint32_t *)am), *((uint32_t *)bm)) &&
           nonstrict_mask16(*((uint16_t *)(a+4)), *((uint16_t *)(b+4)), *((uint16_t *)(am+4)), *((uint16_t *)(bm+4)));
}

static inline bool CONST_ATTR
nonstrict_dlvlan(uint16_t a, uint16_t b, uint32_t aw, uint32_t bw) {
    uint32_t f = OFPFW_DL_VLAN;
    return (wc(bw, f) && wc(aw, f)) ||
          (~wc(bw, f) && (wc(aw, f) || (a == OFPVID_ANY && b != OFPVID_NONE) || a == b));
}

static inline bool CONST_ATTR
nonstrict_dlvpcp(uint16_t avlan, uint16_t apcp, uint16_t bvlan, uint16_t bpcp, uint32_t aw, uint32_t bw) {
    uint32_t f = OFPFW_DL_VLAN_PCP;
    return (wc(bw, f) && wc(aw, f)) ||
          (~wc(bw, f) && (wc(aw, f) || (avlan == OFPVID_NONE && bvlan == OFPVID_NONE) || apcp == bpcp));
}

/* Tells whether the two match structures match (non-strict). */
bool
match_std_nonstrict(struct ofl_match_standard *a, struct ofl_match_standard *b) {
    return nonstrict_wild32(a->in_port, b->in_port, a->wildcards, b->wildcards, OFPFW_IN_PORT) &&
           nonstrict_dladdr(a->dl_src, b->dl_src, a->dl_src_mask, b->dl_src_mask) &&
           nonstrict_dladdr(a->dl_dst, b->dl_dst, a->dl_dst_mask, b->dl_dst_mask) &&
           nonstrict_dlvlan(a->dl_vlan, b->dl_vlan, a->wildcards, b->wildcards) &&
           nonstrict_dlvpcp(a->dl_vlan, a->dl_vlan_pcp, b->dl_vlan, b->dl_vlan_pcp, a->wildcards, b->wildcards) &&
           nonstrict_wild16(a->dl_type, b->dl_type, a->wildcards, b->wildcards, OFPFW_DL_TYPE) &&
           nonstrict_wild8 (a->nw_tos, b->nw_tos, a->wildcards, b->wildcards, OFPFW_NW_TOS) &&
           nonstrict_wild8 (a->nw_proto, b->nw_proto, a->wildcards, b->wildcards, OFPFW_NW_PROTO) &&
           nonstrict_mask32(a->nw_src, b->nw_src, a->nw_src_mask, b->nw_src_mask) &&
           nonstrict_mask32(a->nw_dst, b->nw_dst, a->nw_dst_mask, b->nw_dst_mask) &&
           nonstrict_wild16(a->tp_src, b->tp_src, a->wildcards, b->wildcards, OFPFW_TP_SRC) &&
           nonstrict_wild16(a->tp_dst, b->tp_dst, a->wildcards, b->wildcards, OFPFW_TP_DST) &&
           nonstrict_wild32(a->mpls_label, b->mpls_label, a->wildcards, b->wildcards, OFPFW_MPLS_LABEL) &&
           nonstrict_wild8 (a->mpls_tc, b->mpls_tc, a->wildcards, b->wildcards, OFPFW_MPLS_TC) &&
           nonstrict_mask64(a->metadata, b->metadata, a->metadata_mask, b->metadata_mask);
}



static inline bool CONST_ATTR
pkt_wild16(uint16_t a, uint16_t b, uint32_t aw, uint32_t f) {
    return wc(aw, f) || a == b;
}

static inline bool CONST_ATTR
pkt_wild32(uint32_t a, uint32_t b, uint32_t aw, uint32_t f) {
    return wc(aw, f) || a == b;
}

static inline bool CONST_ATTR
pkt_mask16(uint16_t a, uint16_t b, uint16_t am) {
    return (~am & (a^b)) == 0;
}

static inline bool CONST_ATTR
pkt_mask32(uint32_t a, uint32_t b, uint32_t am) {
    return (~am & (a^b)) == 0;
}

static inline bool CONST_ATTR
pkt_mask64(uint64_t a, uint64_t b, uint64_t am) {
    return (~am & (a^b)) == 0;
}

static inline bool
pkt_dladdr(uint8_t *a, uint8_t *b, uint8_t *am) {
    return pkt_mask32(*((uint32_t *)a), *((uint32_t *)b), *((uint32_t *)am)) &&
           pkt_mask16(*((uint16_t *)(a+4)), *((uint16_t *)(b+4)), *((uint16_t *)(am+4)));
}

/* Tells whether the packet matches the given match strucutre.
 * It relies on the standard match helper structure in pipeline packet.
 */
bool
match_std_pkt(struct ofl_match_standard *m, struct pl_pkt *pl_pkt) {
    /* TODO
     * A flow entry that specifies an Ethernet type of 0x05FF, matches all 802.3 frames
     * without a SNAP header and those with SNAP headers that do not have an OUI of 0x000000.
     */
    struct match_std_helper *p = (struct match_std_helper *)&(pl_pkt->std_protos);

    // valid packet ?
    if (p->eth == NULL) {
        logger_log(pl_pkt->logger, LOG_DEBUG, "No match: non-ethernet packet.");
        return false;
    }

    // meta information
    if (!pkt_wild32(m->in_port, pl_pkt->in_port, m->wildcards, OFPFW_IN_PORT)) {
        logger_log(pl_pkt->logger, LOG_DEBUG, "No match: input port.");
        return false;
    }

    if (!pkt_mask64(m->metadata, pl_pkt->metadata, m->metadata_mask)) {
        logger_log(pl_pkt->logger, LOG_DEBUG, "No match: metadata.");
        return false;
    }

    if (!pkt_dladdr(m->dl_src, p->eth->eth_src, m->dl_src_mask)) {
        logger_log(pl_pkt->logger, LOG_DEBUG, "No match: dl source.");
        return false;
    }

    if (!pkt_dladdr(m->dl_dst, p->eth->eth_dst, m->dl_dst_mask)) {
        logger_log(pl_pkt->logger, LOG_DEBUG, "No match: dl destination.");
        return false;
    }

    if (!pkt_wild16(m->dl_type, p->dl_type, m->wildcards, OFPFW_DL_TYPE)) {
        logger_log(pl_pkt->logger, LOG_DEBUG, "No match: dl type.");
        return false;
    }

    if (p->vlan == NULL) {
        if (!wc(m->wildcards, OFPFW_DL_VLAN) && (m->dl_vlan != OFPVID_NONE)) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: expected vlan (1).");
            return false;
        }
        //TODO is this a correct interpretation?
        if (!wc(m->wildcards, OFPFW_DL_VLAN_PCP) && (m->dl_vlan != htons(OFPVID_NONE))) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: expected vlan (2).");
            return false;
        }
    } else {
        if (!wc(m->wildcards, OFPFW_DL_VLAN) && (m->dl_vlan != htons(OFPVID_ANY)) &&
            ((ntohs(p->vlan->vlan_tci) & VLAN_VID_MASK) >> VLAN_VID_SHIFT) != ntohs(m->dl_vlan)) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: vlan vid.");
            return false;
        }
        if (!wc(m->wildcards, OFPFW_DL_VLAN_PCP) &&
            ((ntohs(p->vlan->vlan_tci) & VLAN_PCP_MASK) >> VLAN_PCP_SHIFT) != m->dl_vlan_pcp) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: vlan pcp.");
            return false;
        }
    }

    // if there was no explicit match on dl_type, no need to go further
    if (wc(m->wildcards, OFPFW_DL_TYPE)) {
        logger_log(pl_pkt->logger, LOG_DEBUG, "Match ok: dl.");
        return true;
    }

    if (p->mpls == NULL) {
        //TODO superfluous?
        if ((m->dl_type == htons(ETH_TYPE_MPLS) || m->dl_type == htons(ETH_TYPE_MPLS_MCAST))) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: expected mpls.");
            return false;
        }
    } else {
        if (!wc(m->wildcards, OFPFW_MPLS_LABEL) &&
            ((ntohl(p->mpls->fields) & MPLS_LABEL_MASK) >> MPLS_LABEL_SHIFT) != ntohl(m->mpls_label)) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: mpls label.");
            return false;
        }
        if (!wc(m->wildcards, OFPFW_MPLS_TC) &&
            ((ntohl(p->mpls->fields) & MPLS_TC_MASK) >> MPLS_TC_SHIFT) != m->mpls_tc) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: mpls tc.");
            return false;
        }

        //no need to check beyond mpls
        logger_log(pl_pkt->logger, LOG_DEBUG, "Match ok: mpls.");
        return true;
    }

    if (p->arp == NULL) {
        //TODO superfluous?
        if (m->dl_type == htons(ETH_TYPE_ARP)) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: expected arp.");
            return false;
        }
    } else {
        //TODO superfluous?
        if (m->dl_type != htons(ETH_TYPE_ARP)) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: did not expect arp.");
            return false;
        }

        //TODO is this a correct interpretation
        if ((p->arp->ar_hrd != htons(1)) ||
            (p->arp->ar_pro != htons(ETH_TYPE_IPV4)) ||
            (p->arp->ar_hln != htons(ETH_ADDR_LEN)) ||
            (p->arp->ar_pln != 4)) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: arp type.");
            return false;
        }

        //TODO is this a correct interpretation
        if (ntohs(p->arp->ar_op) > 0xff) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: arp op range.");
            return false;
        }

        if (!pkt_wild16(m->nw_proto, p->arp->ar_op, m->wildcards, OFPFW_NW_PROTO)) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: arp op.");
            return false;
        }

        if (!pkt_mask32(m->nw_src, p->arp->ar_spa, m->nw_src_mask)) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: arp src.");
            return false;
        }

        if (!pkt_mask32(m->nw_dst, p->arp->ar_tpa, m->nw_dst_mask)) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: arp dst.");
            return false;
        }

        logger_log(pl_pkt->logger, LOG_DEBUG, "Match ok: arp.");
        return true;
    }

    if (p->ipv4 == NULL) {
        //TODO superfluous?
        if (m->dl_type == htons(ETH_TYPE_IPV4)) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: expected ipv4.");
            return false;
        }
    } else {
        //TODO superfluous?
        if (m->dl_type != htons(ETH_TYPE_IPV4)) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: did not expect ipv4.");
            return false;
        }
        if (!wc(m->wildcards, OFPFW_NW_TOS) && (p->ipv4->ip_tos != m->nw_tos)) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: ip tos.");
            return false;
        }
        if (!wc(m->wildcards, OFPFW_NW_PROTO) && (p->ipv4->ip_proto != m->nw_proto)) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: nw proto.");
            return false;
        }
        if (!pkt_mask32(m->nw_src, p->ipv4->ip_src, m->nw_src_mask)) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: nw src.");
            return false;
        }
        if (!pkt_mask32(m->nw_dst, p->ipv4->ip_dst, m->nw_dst_mask)) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: nw dst.");
            return false;
        }
    }

    // if there was no explicit match on nw_proto, no need to go further
    if (wc(m->wildcards, OFPFW_NW_PROTO)) {
        logger_log(pl_pkt->logger, LOG_DEBUG, "Match ok: ipv4.");
        return true;
    }

    // transport is wildcarded, no need to go further
    if (wc(m->wildcards, OFPFW_TP_SRC) && wc(m->wildcards, OFPFW_TP_DST)) {
        logger_log(pl_pkt->logger, LOG_DEBUG, "Match ok: transport.");
        return true;
    }

    if (p->tcp != NULL) {
        if (m->nw_proto != IPPROTO_TCP) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: expected tcp.");
            return false;
        }
        if (!wc(m->wildcards, OFPFW_TP_SRC) && (p->tcp->tcp_src != m->tp_src)) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: tcp src.");
            return false;
        }
        if (!wc(m->wildcards, OFPFW_TP_DST) && (p->tcp->tcp_dst != m->tp_dst)) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: tcp dst.");
            return false;
        }
        logger_log(pl_pkt->logger, LOG_DEBUG, "Match ok: tcp.");
        return true;
    }

    if (p->udp != NULL) {
        if (m->nw_proto != IPPROTO_UDP) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: expected udp.");
            return false;
        }
        if (!wc(m->wildcards, OFPFW_TP_SRC) && (p->udp->udp_src != m->tp_src)) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: udp src.");
            return false;
        }
        if (!wc(m->wildcards, OFPFW_TP_DST) && (p->udp->udp_dst != m->tp_dst)) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: udp dst.");
            return false;
        }
        logger_log(pl_pkt->logger, LOG_DEBUG, "Match ok: tcp.");
        return true;
    }

    if (p->sctp != NULL) {
        if (m->nw_proto != IPPROTO_SCTP) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: expected sctp.");
            return false;
        }
        if (!wc(m->wildcards, OFPFW_TP_SRC) && (p->sctp->sctp_src != m->tp_src)) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: sctp src.");
            return false;
        }
        if (!wc(m->wildcards, OFPFW_TP_DST) && (p->sctp->sctp_dst != m->tp_dst)) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: sctp dst.");
            return false;
        }
        return true;
    }

    if (p->icmp != NULL) {
        if (m->nw_proto != IPPROTO_ICMP) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: expected icmp.");
            return false;
        }
        if (!wc(m->wildcards, OFPFW_TP_SRC) && (p->icmp->icmp_type != ntohs(m->tp_src))) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: icmp type.");
            return false;
        }
        if (!wc(m->wildcards, OFPFW_TP_DST) && (p->icmp->icmp_code != ntohs(m->tp_dst))) {
            logger_log(pl_pkt->logger, LOG_DEBUG, "No match: icmp code.");
            return false;
        }
        return true;
    }

    // expected transport, but none found
    logger_log(pl_pkt->logger, LOG_DEBUG, "No match: expected transport.");
    return false;
}
