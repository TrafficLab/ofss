/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef PKT_BUF_H
#define PKT_BUF_H 1

#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include "lib/message_box.h"

#define HEADROOM  128
#define TAILROOM  128

struct pkt_buf {
    struct list_node list;

    uint8_t  *base;
    size_t    base_len;
    uint8_t  *data;
    size_t    data_len;
};



static inline struct pkt_buf *
pkt_buf_new(size_t len) {
    struct pkt_buf *pkt_buf = malloc(sizeof(struct pkt_buf));

    pkt_buf->base_len = HEADROOM + len + TAILROOM;
    pkt_buf->base = malloc(pkt_buf->base_len);
    pkt_buf->data_len = 0;
    pkt_buf->data = pkt_buf->base + HEADROOM;

    return pkt_buf;
}

static inline struct pkt_buf *
pkt_buf_new_use(void *data, size_t data_len) {
    struct pkt_buf *pkt_buf = malloc(sizeof(struct pkt_buf));

    pkt_buf->base_len = data_len;
    pkt_buf->base  = data;
    pkt_buf->data_len = data_len;
    pkt_buf->data  = data;

    return pkt_buf;
}

void
pkt_buf_free(struct pkt_buf *pkt_buf);

void
pkt_buf_clear(struct pkt_buf *pkt_buf);

//NOTE: if null is provided, a new buf is allocated
struct pkt_buf *
pkt_buf_clone(struct pkt_buf *pkt_buf, struct pkt_buf *clone);

static inline size_t
pkt_buf_headroom(struct pkt_buf *pkt_buf) {
    return (pkt_buf->data - pkt_buf->base);
}

static inline size_t
pkt_buf_tailroom(struct pkt_buf *pkt_buf) {
    return pkt_buf->base_len - pkt_buf_headroom(pkt_buf) - pkt_buf->data_len;
}

ptrdiff_t
pkt_buf_ensure_len(struct pkt_buf *pkt_buf, size_t new_data_len);

ptrdiff_t
pkt_buf_ensure_headroom(struct pkt_buf *pkt_buf, size_t new_headroom_len);


#endif /* PKT_BUF_H */
