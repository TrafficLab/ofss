/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef PROTOCOL_STACK_H
#define PROTOCOL_STACK_H 1

#include <sys/types.h>

/* Name of the known protocols. */
enum protocol {
    PROTO_ETH,
    PROTO_VLAN,
    PROTO_MPLS,
    PROTO_IPV4,
    PROTO_ARP,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_SCTP,
    PROTO_ICMP,
    PROTO_PAYLOAD
};

/* Subtype for protocols (currently used for ETH only). */
enum protocol_type {
    PROTO_TYPE_OK,
    PROTO_TYPE_INVALID,
    PROTO_TYPE_ETH_2,
    PROTO_TYPE_ETH_SNAP
};

/* An entry in the protocol stack of the pipeline packet. */
struct stack_entry {
    enum protocol        protocol;
    enum protocol_type   type;
    ptrdiff_t            offset;
    size_t               length;
};

void
proto_stack_ensure_size(struct stack_entry (**stack)[], size_t *stack_size, size_t required_size);

ssize_t
proto_stack_indexof(struct stack_entry (*stack)[], size_t stack_depth, enum protocol proto);

ssize_t
proto_stack_indexof_last(struct stack_entry (*stack)[], size_t stack_depth, enum protocol proto);

ssize_t
proto_stack_indexof_arr(struct stack_entry (*stack)[], size_t stack_depth, enum protocol (*protos)[], size_t protos_size);

ssize_t
proto_stack_indexof_arr_last(struct stack_entry (*stack)[], size_t stack_depth, enum protocol (*protos)[], size_t protos_size);

void
proto_stack_push(struct stack_entry (**stack)[], size_t *stack_depth, size_t *stack_size,
                 size_t idx, enum protocol proto, enum protocol_type type, size_t len);

void
proto_stack_pop(struct stack_entry (*stack)[], size_t *stack_depth, size_t idx);

#endif /* PROTOCOL_STACK_H */
