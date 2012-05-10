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
 * Helper functions for the protocol stack of the pipeline packet.
 */
#include <assert.h>
#include <stdlib.h>
#include "lib/util.h"
#include "protocol_stack.h"

/* Ensures the stack has the required size. */
void
proto_stack_ensure_size(struct stack_entry (**stack)[], size_t *stack_size, size_t required_size) {
    if (*stack_size < required_size) {
        while ((*stack_size) < required_size) {
            (*stack_size) *=2;
        }
        (*stack) = realloc(*stack, sizeof(struct stack_entry) * (*stack_size));
    }
}

/* Returns the index of the first occurrence of the given protocol layer in the stack, or -1. */
ssize_t
proto_stack_indexof(struct stack_entry (*stack)[], size_t stack_depth, enum protocol proto) {
    size_t i;
    for (i=0; i < stack_depth; i++) {
        if ((*stack)[i].protocol == proto) {
            return i;
        }
    }

    return -1;
}

/* Returns the index of the last occurrence of the given protocol layer in the stack, or -1. */
ssize_t
proto_stack_indexof_last(struct stack_entry (*stack)[], size_t stack_depth, enum protocol proto) {
    ssize_t i;
    for (i=stack_depth - 1; i >= 0; i--) {
        if ((*stack)[i].protocol == proto) {
            return i;
        }
    }

    return -1;
}


/* Returns the index of the first occurrence of the given protocol layers in the stack, or -1. */
ssize_t
proto_stack_indexof_arr(struct stack_entry (*stack)[], size_t stack_depth, enum protocol (*protos)[], size_t protos_size) {
    size_t i, j;
    for (i=0; i < stack_depth; i++) {
        for (j=0; j < protos_size; j++) {
            if ((*stack)[i].protocol == (*protos)[j]) {
                return i;
            }
        }
    }

    return -1;
}

/* Returns the index of the last occurrence of the given protocol layers in the stack, or -1. */
ssize_t
proto_stack_indexof_arr_last(struct stack_entry (*stack)[], size_t stack_depth, enum protocol (*protos)[], size_t protos_size) {
    ssize_t i;
    size_t j;
    for (i=stack_depth - 1; i >= 0; i--) {
        for (j=0; j < protos_size; j++) {
            if ((*stack)[i].protocol == (*protos)[j]) {
                return i;
            }
        }
    }

    return -1;
}

/* Pushes the given protocol to the stack at the given location. */
void
proto_stack_push(struct stack_entry (**stack)[], size_t *stack_depth, size_t *stack_size,
                 size_t idx, enum protocol proto, enum protocol_type type, size_t len) {
    assert(*stack_depth >= idx);

    proto_stack_ensure_size(stack, stack_size, (*stack_depth) + 1);

    size_t i;
    for (i= (*stack_depth); i > idx ; i--) {
        (**stack)[i] = (**stack)[i-1];
        (**stack)[i].offset += len;
    }

    (**stack)[idx] = (struct stack_entry) {.protocol = proto, .type = type,
                                          .offset = (**stack)[idx].offset, .length = len};
    (*stack_depth)++;
}

/* Pops the protocol from the stack at the given location. */
void
proto_stack_pop(struct stack_entry (*stack)[], size_t *stack_depth, size_t idx) {
    assert(*stack_depth > idx);
    (*stack_depth)--;

    size_t proto_len = (*stack)[idx].length;

    size_t i;
    for (i=idx; i < *stack_depth; i++) {
        (*stack)[i] = (*stack)[i+1];
        (*stack)[i].offset -= proto_len;
    }
}
