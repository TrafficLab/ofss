/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef MATCH_STANDARD_H
#define MATCH_STANDARD_H 1

#include <stdbool.h>
#include "oflib/ofl_structs.h"

/* Helper structure for giving relevant indexes into the packet to the
 * match handler. Must be kept up-to-date within pipeline packets. */
struct match_std_helper {
    struct eth_header      *eth;
    struct vlan_header     *vlan;
    uint16_t                dl_type;
    struct mpls_header     *mpls;
    struct ipv4_header     *ipv4;
    struct arp_eth_header  *arp;
    struct tcp_header      *tcp;
    struct udp_header      *udp;
    struct sctp_header     *sctp;
    struct icmp_header     *icmp;
};

struct pl_pkt;

bool
match_std_overlap(struct ofl_match_standard *a, struct ofl_match_standard *b);


bool
match_std_strict(struct ofl_match_standard *a, struct ofl_match_standard *b);

bool
match_std_nonstrict(struct ofl_match_standard *a, struct ofl_match_standard *b);

bool
match_std_pkt(struct ofl_match_standard *m, struct pl_pkt *pl_pkt);



#endif /* MATCH_STANDARD_H */
