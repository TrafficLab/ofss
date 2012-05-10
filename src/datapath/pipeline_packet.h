/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef PIPELINE_PACKET_H
#define PIPELINE_PACKET_H 1

#include <stdbool.h>
#include <stddef.h>
#include "lib/openflow.h"
#include "protocol_stack.h"
#include "match_standard.h"



struct pl_pkt {
    struct logger               *logger;

    struct pkt_buf              *pkt;
    struct stack_entry         (*stack)[];
    size_t                       stack_depth;
    size_t                       stack_size;

    struct act_set              *act_set; /* action set associated with the packet */
    bool                         pkt_out; /* true if the packet arrived in a packet out msg */
    of_port_no_t                 in_port;
    of_metadata_t                metadata;
    of_queue_no_t                queue;
    of_tableid_t                 table_id; /* table in which is processed */

    struct match_std_helper   std_protos;
};

struct pl_pkt *
pl_pkt_new(struct pkt_buf *pkt, bool pkt_out, of_port_no_t in_port);

void
pl_pkt_free(struct pl_pkt *pl_pkt, bool free_pkt);

struct pl_pkt *
pl_pkt_clone(struct pl_pkt *pl_pkt);


char *
pl_pkt_to_string(struct pl_pkt *pl_pkt);

void
pl_pkt_parse(struct pl_pkt *pl_pkt);

bool
pl_pkt_is_ttl_valid(struct pl_pkt *pl_pkt);

bool
pl_pkt_is_fragment(struct pl_pkt *pl_pkt);

#endif /* PIPELINE_PACKET_H */
