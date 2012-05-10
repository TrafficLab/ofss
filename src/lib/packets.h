/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef PACKETS_H
#define PACKETS_H 1

#include <stdint.h>
#include "lib/compiler.h"

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


// bug caused by openflow.h (1.1)
#undef icmp_type
#undef icmp_code

#define ETH_ADDR_LEN           6
struct eth_header {
    uint8_t  eth_dst[ETH_ADDR_LEN];
    uint8_t  eth_src[ETH_ADDR_LEN];
    uint16_t eth_type;
} PACKED_ATTR;

#define ETH_TYPE_2_START       0x0600
#define ETH_TYPE_IPV4          0x0800
#define ETH_TYPE_ARP           0x0806
#define ETH_TYPE_VLAN          0x8100
#define ETH_TYPE_VLAN_PBB      0x88a8
#define ETH_TYPE_MPLS          0x8847
#define ETH_TYPE_MPLS_MCAST    0x8848


struct llc_header {
    uint8_t llc_dsap;
    uint8_t llc_ssap;
    uint8_t llc_cntl;
} PACKED_ATTR;

#define LLC_DSAP_SNAP 0xaa
#define LLC_SSAP_SNAP 0xaa
#define LLC_CNTL_SNAP 3

struct snap_header {
    uint8_t snap_org[3];
    uint16_t snap_type;
} PACKED_ATTR;

#define SNAP_ORG_ETHERNET (uint8_t[]){0,0,0}

struct llc_snap_header {
    struct llc_header llc;
    struct snap_header snap;
} PACKED_ATTR;

struct vlan_header {
    uint16_t vlan_tci;          /* Lowest 12 bits are VLAN ID. */
    uint16_t vlan_next_type;
} PACKED_ATTR;

#define VLAN_VID_MASK 0x0fff
#define VLAN_VID_SHIFT 0
#define VLAN_PCP_MASK 0xe000
#define VLAN_PCP_SHIFT 13
#define VLAN_PCP_BITMASK 0x0007 /* the least 3-bit is valid */

#define VLAN_VID_MAX 4095
#define VLAN_PCP_MAX 7

struct mpls_header {
    uint32_t fields;
} PACKED_ATTR;

#define MPLS_LABEL_MAX   1048575
#define MPLS_TC_MAX            7

#define MPLS_HEADER_LEN 4

#define MPLS_TTL_MASK 0x000000ff
#define MPLS_TTL_SHIFT 0
#define MPLS_S_MASK 0x00000100
#define MPLS_S_SHIFT 8
#define MPLS_TC_MASK 0x00000e00
#define MPLS_TC_SHIFT 9
#define MPLS_LABEL_MASK 0xfffff000
#define MPLS_LABEL_SHIFT 12

struct arp_eth_header {
    /* Generic members. */
    uint16_t ar_hrd;           /* Hardware type. */
    uint16_t ar_pro;           /* Protocol type. */
    uint8_t ar_hln;            /* Hardware address length. */
    uint8_t ar_pln;            /* Protocol address length. */
    uint16_t ar_op;            /* Opcode. */

    /* Ethernet+IPv4 specific members. */
    uint8_t ar_sha[ETH_ADDR_LEN]; /* Sender hardware address. */
    uint32_t ar_spa;           /* Sender protocol address. */
    uint8_t ar_tha[ETH_ADDR_LEN]; /* Target hardware address. */
    uint32_t ar_tpa;           /* Target protocol address. */
} PACKED_ATTR;

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

struct ipv4_header {
    uint8_t ip_ihl_ver;
    uint8_t ip_tos;
    uint16_t ip_tot_len;
    uint16_t ip_id;
    uint16_t ip_frag_off;
    uint8_t ip_ttl;
    uint8_t ip_proto;
    uint16_t ip_csum;
    uint32_t ip_src;
    uint32_t ip_dst;
} PACKED_ATTR;

#define IP_TYPE_ICMP   1
#define IP_TYPE_TCP    6
#define IP_TYPE_UDP   17
#define IP_TYPE_SCTP 132

#define IP_ECN_MASK  0x03
#define IP_DSCP_MASK 0xfc

#define IP_MORE_FRAGMENTS 0x2000 /* More fragments. */
#define IP_FRAG_OFF_MASK  0x1fff /* Fragment offset. */
#define IP_IS_FRAGMENT(ip_frag_off) \
        ((ip_frag_off) & htons(IP_MORE_FRAGMENTS | IP_FRAG_OFF_MASK))

#define IP_VER(ip_ihl_ver) ((ip_ihl_ver) >> 4)
#define IP_IHL(ip_ihl_ver) ((ip_ihl_ver) & 15)

struct icmp_header {
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_csum;
} PACKED_ATTR;

struct udp_header {
    uint16_t udp_src;
    uint16_t udp_dst;
    uint16_t udp_len;
    uint16_t udp_csum;
} PACKED_ATTR;

struct tcp_header {
    uint16_t tcp_src;
    uint16_t tcp_dst;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint16_t tcp_ctl;
    uint16_t tcp_winsz;
    uint16_t tcp_csum;
    uint16_t tcp_urg;
} PACKED_ATTR;

struct sctp_header {
    uint16_t sctp_src;
    uint16_t sctp_dst;
    uint32_t sctp_verif;
    uint32_t sctp_csum;
} PACKED_ATTR;

#endif /* PACKETS_H */
