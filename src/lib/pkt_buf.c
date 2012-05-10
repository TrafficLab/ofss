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
 * A buffer for storing raw packet data.
 */

#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include "lib/list.h"

#define HEADROOM  128
#define TAILROOM  128

struct pkt_buf {
    struct list_node   list;
    uint8_t  *base;
    size_t    base_len;
    uint8_t  *data;
    size_t    data_len;

    void     *private;
};


/* Creates a new empty buffer. */
static inline struct pkt_buf *
pkt_buf_new(size_t len) {
    struct pkt_buf *pkt_buf = malloc(sizeof(struct pkt_buf));

    pkt_buf->base_len = HEADROOM + len + TAILROOM;
    pkt_buf->base = malloc(pkt_buf->base_len);
    pkt_buf->data_len = 0;
    pkt_buf->data = pkt_buf->base + HEADROOM;

    return pkt_buf;
}

/* Frees a buffer, including its packet. */
void
pkt_buf_free(struct pkt_buf *pkt_buf) {
    free(pkt_buf->base);
    free(pkt_buf);
}

/* Sets the buffer to empty. */
void
pkt_buf_clear(struct pkt_buf *pkt_buf) {
    //assert base_len > headroom
    pkt_buf->data_len = 0;
    pkt_buf->data = pkt_buf->base + HEADROOM;
}

/* Clones the buffer data to the new buffer, or to
 * a new buffer if NULL is provided. */
struct pkt_buf *
pkt_buf_clone(struct pkt_buf *pkt_buf, struct pkt_buf *clone) {
    if (clone == NULL) {
        clone = pkt_buf_new(pkt_buf->data_len);
    }

    memcpy(clone->data, pkt_buf->data, pkt_buf->data_len);
    clone->data_len = pkt_buf->data_len;

    return clone;
}

/* Returns the available headroom in the buffer. */
static inline size_t
pkt_buf_headroom(struct pkt_buf *pkt_buf) {
    return (pkt_buf->data - pkt_buf->base);
}

/* Returns the available tailroom in the buffer. */
static inline size_t
pkt_buf_tailroom(struct pkt_buf *pkt_buf) {
    return pkt_buf->base_len - pkt_buf_headroom(pkt_buf) - pkt_buf->data_len;
}

/* Makes sure the buffer is capable of holding that long packet. */
ptrdiff_t
pkt_buf_ensure_len(struct pkt_buf *pkt_buf, size_t new_data_len) {
    if (pkt_buf_tailroom(pkt_buf) + pkt_buf->data_len >= new_data_len) {
        return 0;
    }

    uint8_t *old_base = pkt_buf->base;

    pkt_buf->base_len = pkt_buf_headroom(pkt_buf) + new_data_len;
    pkt_buf->base = realloc(pkt_buf, pkt_buf->base_len);

    ptrdiff_t pdiff = pkt_buf->base == old_base;
    pkt_buf->data += pdiff;

    return pdiff;
}

/* Makes sure the buffer contains that long headroom. */
ptrdiff_t
pkt_buf_ensure_headroom(struct pkt_buf *pkt_buf, size_t new_headroom_len) {
    if (pkt_buf_headroom(pkt_buf) >= new_headroom_len) {
        return 0;
    }

    uint8_t *old_data = pkt_buf->data;

    pkt_buf->base_len = new_headroom_len + pkt_buf->data_len + TAILROOM;
    pkt_buf->base = malloc(pkt_buf->base_len);

    pkt_buf->data = pkt_buf->base + new_headroom_len;

    memcpy(pkt_buf->data, old_data, pkt_buf->data_len);

    return (pkt_buf->data - old_data);
}
