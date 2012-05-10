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
 * Represents a processed packet within the pipeline.
 */

#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include "lib/compiler.h"
#include "lib/openflow.h"
#include "lib/packets.h"
#include "lib/pkt_buf.h"
#include "oflib/ofl.h"
#include "oflib/ofl_print.h"
#include "oflib/ofl_structs.h"
#include "oflib/ofl_utils.h"
#include "pipeline_packet.h"
#include "protocol_stack.h"
#include "action_set.h"


#define INIT_STACK_SIZE 8

// bug caused by openflow.h (1.1)
#undef icmp_type
#undef icmp_code

/* Creates a new pipeline packet. */
struct pl_pkt * MALLOC_ATTR
pl_pkt_new(struct pkt_buf *pkt, bool pkt_out, of_port_no_t in_port) {
    struct pl_pkt *pl_pkt = malloc(sizeof(struct pl_pkt));
    pl_pkt->pkt = pkt;
    pl_pkt->stack = malloc(sizeof(struct stack_entry) * INIT_STACK_SIZE);
    pl_pkt->stack_size = INIT_STACK_SIZE;
    pl_pkt->stack_depth = 0;

    pl_pkt->act_set = action_set_new();
    pl_pkt->pkt_out = pkt_out;
    pl_pkt->metadata = 0ULL;
    pl_pkt->in_port = in_port;
    pl_pkt->queue = 0; // default queue
    pl_pkt->table_id = 0;

    pl_pkt_parse(pl_pkt);

    return pl_pkt;
}

/* Frees the pipeline packet, and optionally the packet itself as well. */
void
pl_pkt_free(struct pl_pkt *pl_pkt, bool free_pkt) {
    if (free_pkt) {
        pkt_buf_free(pl_pkt->pkt);
    }
    free(pl_pkt->stack);
    action_set_free(pl_pkt->act_set);
    free(pl_pkt);
}

/* Creates a clone of the pipeline packet. */
struct pl_pkt * MALLOC_ATTR
pl_pkt_clone(struct pl_pkt *pl_pkt) {
    struct pl_pkt *clone = memcpy(malloc(sizeof(struct pl_pkt)), pl_pkt, sizeof(struct pl_pkt));
    clone->pkt = pkt_buf_clone(pl_pkt->pkt, NULL);
    clone->stack = memcpy(malloc(sizeof(struct stack_entry) * pl_pkt->stack_size), pl_pkt->stack,
                          sizeof(struct stack_entry) * pl_pkt->stack_size);
    clone->act_set = action_set_clone(pl_pkt->act_set);

    return clone;
}

/* Parses the packet: identifies the protocol stack,
 * and updates the standard match helper.
 */
void
pl_pkt_parse(struct pl_pkt *pl_pkt) {
    struct pkt_buf *pkt = pl_pkt->pkt;
    struct match_std_helper *std_protos = &(pl_pkt->std_protos);
    size_t offset = 0;
    pl_pkt->stack_depth = 0;
    memset(&(pl_pkt->std_protos), '\0', sizeof(struct match_std_helper));

    /* Ethernet */
    if (pkt->data_len < offset + sizeof(struct eth_header)) {
        goto payload;
    }

    struct eth_header *eth = (struct eth_header *)(pkt->data + offset);
    std_protos->eth = eth;
    pl_pkt->std_protos.eth = eth;
    uint16_t dl_type;

    proto_stack_ensure_size(&(pl_pkt->stack), &(pl_pkt->stack_size), pl_pkt->stack_depth + 1);
    (*(pl_pkt->stack))[pl_pkt->stack_depth] = (struct stack_entry){.protocol = PROTO_ETH,
                                                             .offset = offset, .length = sizeof(struct eth_header)};
    offset += sizeof(struct eth_header);

    if (ntohs(eth->eth_type) >= ETH_TYPE_2_START) {
        /* Ethernet 2 */
        (*(pl_pkt->stack))[pl_pkt->stack_depth].type = PROTO_TYPE_ETH_2;
        dl_type = eth->eth_type;
        std_protos->dl_type = dl_type;
        pl_pkt->std_protos.dl_type = dl_type;

    } else {
        /* Ethernet 802.3 */
        // TODO compare packet length with ethernet length field for validity
        if (pkt->data_len < offset + sizeof(struct llc_header)) {
            (*(pl_pkt->stack))[pl_pkt->stack_depth].type = PROTO_TYPE_INVALID;
            goto payload;
        }

        struct llc_header *llc = (struct llc_header *)(pkt->data + offset);
        offset += sizeof(struct llc_header);
        (*(pl_pkt->stack))[pl_pkt->stack_depth].length += sizeof(struct llc_header);

        if (!(llc->llc_dsap == LLC_DSAP_SNAP &&
              llc->llc_ssap == LLC_SSAP_SNAP &&
              llc->llc_cntl == LLC_CNTL_SNAP)) {
            (*(pl_pkt->stack))[pl_pkt->stack_depth].type = PROTO_TYPE_INVALID;
            goto payload;
        }

        if (pkt->data_len < offset + sizeof(struct snap_header)) {
            (*(pl_pkt->stack))[pl_pkt->stack_depth].type = PROTO_TYPE_INVALID;
            goto payload;
        }

        struct snap_header *eth_snap = (struct snap_header *)(pkt->data + offset);
        offset += sizeof(struct snap_header);
        (*(pl_pkt->stack))[pl_pkt->stack_depth].length += sizeof(struct snap_header);

        if (memcmp(eth_snap->snap_org, SNAP_ORG_ETHERNET, sizeof(SNAP_ORG_ETHERNET)) != 0) {
            (*(pl_pkt->stack))[pl_pkt->stack_depth].type = PROTO_TYPE_INVALID;
            goto payload;
        }

        (*(pl_pkt->stack))[pl_pkt->stack_depth].protocol = PROTO_TYPE_ETH_SNAP;
        dl_type = eth_snap->snap_type;
        std_protos->dl_type = dl_type;
    }

    pl_pkt->stack_depth++;

    /* VLAN */
    /* skip through rest of VLAN tags */
    while (dl_type == htons(ETH_TYPE_VLAN) || dl_type == htons(ETH_TYPE_VLAN_PBB)) {
        if (pkt->data_len < offset + sizeof(struct vlan_header)) {
            goto payload;
        }

        struct vlan_header *vlan = (struct vlan_header *)(pkt->data + offset);
        if (std_protos->vlan == NULL) { // store first tag
            std_protos->vlan = vlan;
        }

        proto_stack_ensure_size(&(pl_pkt->stack), &(pl_pkt->stack_size), pl_pkt->stack_depth + 1);
        (*(pl_pkt->stack))[pl_pkt->stack_depth] = (struct stack_entry){.protocol = PROTO_VLAN,
                                                                 .offset = offset, .length = sizeof(struct vlan_header)};
        pl_pkt->stack_depth++;

        offset += sizeof(struct vlan_header);
        dl_type = vlan->vlan_next_type;
        std_protos->dl_type = dl_type;
    }


    /* MPLS */
    if (dl_type == htons(ETH_TYPE_MPLS) ||
        dl_type == htons(ETH_TYPE_MPLS_MCAST)) {

        struct mpls_header *mpls;

        do {
            if (pkt->data_len < offset + sizeof(struct mpls_header)) {
                goto payload;
            }

            mpls = (struct mpls_header *)(pkt->data + offset);
            if (std_protos->mpls == NULL) { // store first label
                std_protos->mpls = mpls;
            }

            proto_stack_ensure_size(&(pl_pkt->stack), &(pl_pkt->stack_size), pl_pkt->stack_depth + 1);
            (*(pl_pkt->stack))[pl_pkt->stack_depth] = (struct stack_entry){.protocol = PROTO_MPLS,
                                                                     .offset = offset, .length = sizeof(struct mpls_header)};
            pl_pkt->stack_depth++;

            offset += sizeof(struct mpls_header);
        } while ((ntohl(mpls->fields) & MPLS_S_MASK) == 0);

        /* Peek below MPLS for IPv4 */
        if (pkt->data_len < offset + sizeof(struct ipv4_header)) {
            goto payload;
        }

        struct ipv4_header *ipv4 = (struct ipv4_header *)(pkt->data + offset);
        if (IP_VER(ipv4->ip_ihl_ver) == 0x04) {
            dl_type = htons(ETH_TYPE_IPV4);
        } else {
            goto payload;
        }
    }

    /* ARP */
    if (dl_type == htons(ETH_TYPE_ARP)) {
        if (pkt->data_len < offset + sizeof(struct arp_eth_header)) {
            goto payload;
        }

        std_protos->arp = (struct arp_eth_header *)(pkt->data + offset);

        proto_stack_ensure_size(&(pl_pkt->stack), &(pl_pkt->stack_size), pl_pkt->stack_depth + 1);
        (*(pl_pkt->stack))[pl_pkt->stack_depth] = (struct stack_entry){.protocol = PROTO_ARP,
                                                                 .offset = offset, .length = sizeof(struct arp_eth_header)};
        pl_pkt->stack_depth++;
        offset += sizeof(struct arp_eth_header);
        goto payload;
    }

    /* Network Layer */
    if (dl_type == htons(ETH_TYPE_IPV4)) {
        if (pkt->data_len < offset + sizeof(struct ipv4_header)) {
            goto payload;
        }

        struct ipv4_header *ipv4 = (struct ipv4_header *)(pkt->data + offset);
        if (std_protos->dl_type == htons(ETH_TYPE_IPV4)) {
            // store protocol only if it is not behind MPLS
            std_protos->ipv4 = ipv4;
        }

        proto_stack_ensure_size(&(pl_pkt->stack), &(pl_pkt->stack_size), pl_pkt->stack_depth + 1);
        (*(pl_pkt->stack))[pl_pkt->stack_depth] = (struct stack_entry){.protocol = PROTO_IPV4,
                                                                 .offset = offset, .length = IP_IHL(ipv4->ip_ihl_ver) * 4};
        pl_pkt->stack_depth++;
        offset += IP_IHL(ipv4->ip_ihl_ver) * 4;

        if (IP_IS_FRAGMENT(ipv4->ip_frag_off)) {
            /* No further processing for fragmented IPv4 */
            goto payload;
        }


        /* Transport */
        if (ipv4->ip_proto == IP_TYPE_TCP) {
            if (pkt->data_len < offset + sizeof(struct tcp_header)) {
                goto payload;
            }

            if (std_protos->dl_type == htons(ETH_TYPE_IPV4)) {
                // store protocol only if it is not behind MPLS
                std_protos->tcp = (struct tcp_header *)(pkt->data + offset);
            }

            proto_stack_ensure_size(&(pl_pkt->stack), &(pl_pkt->stack_size), pl_pkt->stack_depth + 1);
            (*(pl_pkt->stack))[pl_pkt->stack_depth] = (struct stack_entry){.protocol = PROTO_TCP,
                                                                     .offset = offset, .length = sizeof(struct tcp_header)};
            pl_pkt->stack_depth++;
            offset += sizeof(struct tcp_header);
            goto payload;

        } else if (ipv4->ip_proto == IP_TYPE_UDP) {
            if (pkt->data_len < offset + sizeof(struct udp_header)) {
                goto payload;
            }


            if (std_protos->dl_type == htons(ETH_TYPE_IPV4)) {
                // store protocol only if it is not behind MPLS
                std_protos->udp = (struct udp_header *)(pkt->data + offset);
            }

            proto_stack_ensure_size(&(pl_pkt->stack), &(pl_pkt->stack_size), pl_pkt->stack_depth + 1);
            (*(pl_pkt->stack))[pl_pkt->stack_depth] = (struct stack_entry){.protocol = PROTO_UDP,
                                                                     .offset = offset, .length = sizeof(struct udp_header)};
            pl_pkt->stack_depth++;
            offset += sizeof(struct tcp_header);
            goto payload;

        } else if (ipv4->ip_proto == IP_TYPE_ICMP) {
            if (pkt->data_len < offset + sizeof(struct icmp_header)) {
                goto payload;
            }

            if (std_protos->dl_type == htons(ETH_TYPE_IPV4)) {
                // store protocol only if it is not behind MPLS
                std_protos->icmp = (struct icmp_header *)(pkt->data + offset);
            }

            proto_stack_ensure_size(&(pl_pkt->stack), &(pl_pkt->stack_size), pl_pkt->stack_depth + 1);
            (*(pl_pkt->stack))[pl_pkt->stack_depth] = (struct stack_entry){.protocol = PROTO_ICMP,
                                                                     .offset = offset, .length = sizeof(struct icmp_header)};
            pl_pkt->stack_depth++;
            offset += sizeof(struct icmp_header);
            goto payload;

        } else if (ipv4->ip_proto == IP_TYPE_SCTP) {
            if (pkt->data_len < offset + sizeof(struct sctp_header)) {
                goto payload;
            }

            if (std_protos->dl_type == htons(ETH_TYPE_IPV4)) {
                // store protocol only if it is not behind MPLS
                std_protos->sctp = (struct sctp_header *)(pkt->data + offset);
            }

            proto_stack_ensure_size(&(pl_pkt->stack), &(pl_pkt->stack_size), pl_pkt->stack_depth + 1);
            (*(pl_pkt->stack))[pl_pkt->stack_depth] = (struct stack_entry){.protocol = PROTO_SCTP,
                                                                     .offset = offset, .length = sizeof(struct sctp_header)};
            pl_pkt->stack_depth++;
            offset += sizeof(struct sctp_header);
            goto payload;
        }
    }

    payload: {
        if (offset < pkt->data_len) {
            proto_stack_ensure_size(&(pl_pkt->stack), &(pl_pkt->stack_size), pl_pkt->stack_depth + 1);
            (*(pl_pkt->stack))[pl_pkt->stack_depth] = (struct stack_entry){.protocol = PROTO_PAYLOAD,
                                                                     .offset = offset, .length = (pkt->data_len - offset)};
            pl_pkt->stack_depth++;
        }
    }

}


/* Tells whether TTL's are valid within the packet. */
bool
pl_pkt_is_ttl_valid(struct pl_pkt *pl_pkt) {
    size_t i;
    for (i=0; i < pl_pkt->stack_depth; i++) {
        if ((*(pl_pkt->stack))[i].protocol == PROTO_MPLS) {
            struct mpls_header *mpls = (struct mpls_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[i].offset);
            uint32_t ttl = ntohl(mpls->fields) & MPLS_TTL_MASK;

            if (ttl <= 1) {
                return false;
            }
        }
        if ((*(pl_pkt->stack))[i].protocol == PROTO_IPV4) {
            struct ipv4_header *ipv4 = (struct ipv4_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[i].offset);
            if (ipv4->ip_ttl <= 1) {
                return false;
            }
        }
    }

    return true;
}

/* Tells whether the packet is a fragment. */
bool
pl_pkt_is_fragment(struct pl_pkt *pl_pkt) {
    size_t i;
    for (i=0; i < pl_pkt->stack_depth; i++) {
        if ((*(pl_pkt->stack))[i].protocol == PROTO_IPV4) {
            struct ipv4_header *ipv4 = (struct ipv4_header *)(pl_pkt->pkt->data + (*(pl_pkt->stack))[i].offset);
            if (IP_IS_FRAGMENT(ipv4->ip_frag_off)) {
                return true;
            }
        }
    }

    return false;
}


/* Prints a stack entry of the packet. */
static void
entry_print(FILE *stream, struct stack_entry *entry, uint8_t *raw) {
    switch(entry->protocol) {
        case PROTO_ETH: {
            struct eth_header *eth = (struct eth_header *)(raw + entry->offset);
            if (entry->type == PROTO_TYPE_INVALID) {
                fprintf(stream, "Eth{invalid}");
            } else if (entry->type == PROTO_TYPE_ETH_SNAP) {
                struct snap_header *snap = (struct snap_header *)(raw + entry->offset + sizeof(struct eth_header) + sizeof(struct llc_header));
                fprintf(stream, "EthSnap{src=\""ETH_ADDR_FMT"\", dst=\""ETH_ADDR_FMT"\", type=\"0x%x\"}",
                        ETH_ADDR_ARGS(eth->eth_src), ETH_ADDR_ARGS(eth->eth_dst), ntohs(snap->snap_type));
            } else {
                fprintf(stream, "Eth{src=\""ETH_ADDR_FMT"\", dst=\""ETH_ADDR_FMT"\", type=\"0x%x\"}",
                        ETH_ADDR_ARGS(eth->eth_src), ETH_ADDR_ARGS(eth->eth_dst), ntohs(eth->eth_type));
            }
            break;
        }
        case PROTO_VLAN: {
            struct vlan_header *vlan = (struct vlan_header *)(raw + entry->offset);
            fprintf(stream, "Vlan{vid=\"%u\", pcp=\"%u\", type=\"0x%x\"}",
                    (ntohs(vlan->vlan_tci) & VLAN_VID_MASK) >> VLAN_VID_SHIFT,
                    (ntohs(vlan->vlan_tci) & VLAN_PCP_MASK) >> VLAN_PCP_SHIFT,
                    ntohs(vlan->vlan_next_type));
            break;
        }
        case PROTO_MPLS: {
            struct mpls_header *mpls = (struct mpls_header *)(raw + entry->offset);
            fprintf(stream, "Mpls{label=\"%u\", tc=\"%u\", s=\"%u\", ttl=\"%u\"}",
                             (ntohl(mpls->fields) & MPLS_LABEL_MASK) >> MPLS_LABEL_SHIFT,
                             (ntohl(mpls->fields) & MPLS_TC_MASK) >> MPLS_TC_SHIFT,
                             (ntohl(mpls->fields) & MPLS_S_MASK) >> MPLS_S_SHIFT,
                             (ntohl(mpls->fields) & MPLS_TTL_MASK) >> MPLS_TTL_SHIFT);
            break;
        }
        case PROTO_IPV4: {
            struct ipv4_header *ipv4 = (struct ipv4_header *)(raw + entry->offset);
            fprintf(stream, "Ipv4{src=\""IP_FMT"\", dst=\""IP_FMT"\", tos=\"0x%x\", ecn=\"0x%x\" proto=\"%u\", ttl=\"%u\"}",
                    IP_ARGS(&ipv4->ip_src), IP_ARGS(&ipv4->ip_dst), ipv4->ip_tos & IP_DSCP_MASK, ipv4->ip_tos & IP_ECN_MASK, ipv4->ip_proto, ipv4->ip_ttl);
            break;
        }
        case PROTO_ARP: {
            fprintf(stream, "Arp{");
            struct arp_eth_header *arp = (struct arp_eth_header *)(raw + entry->offset);
            if (ntohs(arp->ar_hrd) == 1 && ntohs(arp->ar_pro) == ETH_TYPE_IPV4 &&
                arp->ar_hln == ETH_ADDR_LEN && arp->ar_pln == 4) {

                if (ntohs(arp->ar_op) <= 0xff) {
                    fprintf(stream, "op=\"0x%x\", ", ntohs(arp->ar_op));

                    if (ntohs(arp->ar_op) == ARP_OP_REQUEST || ntohs(arp->ar_op) == ARP_OP_REPLY) {
                        fprintf(stream, "src=\""IP_FMT"\", dst=\""IP_FMT"\"",
                                IP_ARGS(&arp->ar_spa), IP_ARGS(&arp->ar_tpa));
                    }
                }
            }

            fprintf(stream, "}");
            break;
        }
        case PROTO_TCP: {
            struct tcp_header *tcp = (struct tcp_header *)(raw + entry->offset);
            fprintf(stream, "Tcp{src=\"%u\", dst=\"%u\"}", ntohs(tcp->tcp_src), ntohs(tcp->tcp_dst));
            break;
        }
        case PROTO_UDP: {
            struct udp_header *udp = (struct udp_header *)(raw + entry->offset);
            fprintf(stream, "Udp{src=\"%u\", dst=\"%u\"}", ntohs(udp->udp_src), ntohs(udp->udp_dst));
            break;
        }
        case PROTO_SCTP: {
            struct sctp_header *sctp = (struct sctp_header *)(raw + entry->offset);
            fprintf(stream, "Sctp{src=\"%u\", dst=\"%u\"}", ntohs(sctp->sctp_src), ntohs(sctp->sctp_dst));
            break;
        }
        case PROTO_ICMP: {
            struct icmp_header *icmp = (struct icmp_header *)(raw + entry->offset);
            fprintf(stream, "Icmp{type=\"%u\", code=\"%u\"}", icmp->icmp_type, icmp->icmp_code);
            break;
        }
        case PROTO_PAYLOAD: {
            fprintf(stream, "Payload{len=\"%zu\"}", entry->length);
            break;
        }
    }
}

/* Prints the protocol stack in the packet. */
static void
stack_print(FILE *stream, struct pl_pkt *pl_pkt) {
    fprintf(stream, "[");
    size_t i;
    for (i=0; i < pl_pkt->stack_depth; i++) {
        entry_print(stream, &(*(pl_pkt->stack))[i], pl_pkt->pkt->data);
    }
    fprintf(stream, "]");
}

/* Prints the packet. */
char * MALLOC_ATTR
pl_pkt_to_string(struct pl_pkt *pl_pkt) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    fprintf(stream, "pl_pkt{len=%d, in=\"", pl_pkt->pkt->data_len);
    ofl_port_print(stream, pl_pkt->in_port);
    fprintf(stream, "\", actset=");
    action_set_print(stream, pl_pkt->act_set);
    fprintf(stream, ", queue=\"");
    ofl_port_print(stream, pl_pkt->queue);
    fprintf(stream, "\", meta=\"%"PRIx64"\", proto=", ntoh64(pl_pkt->metadata));
    stack_print(stream, pl_pkt);
    fprintf(stream, "}");

    fclose(stream);
    return str;
}
