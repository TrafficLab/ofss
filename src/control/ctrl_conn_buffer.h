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
 * A connection-buffer for storing and combining partial messages.
 */

#ifndef CTRL_CONN_BUFFER_H
#define CTRL_CONN_BUFFER_H 1

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "lib/compiler.h"

struct buffer {
    uint8_t  *buf;
    size_t    len;
    size_t    data_len;
};

/* Create a new buffer with the given size. */
static inline MALLOC_ATTR struct buffer *
buffer_new(size_t len) {
    struct buffer *b = malloc(sizeof(struct buffer));
    b->buf      = malloc(len);
    b->len      = len;
    b->data_len = 0;

    return b;
}

/* Free the buffer. */
static inline void
buffer_free(struct buffer *b) {
    free(b->buf);
    free(b);
}

/* Returns the pointer to the data stored in the buffer. */
static inline uint8_t *
buffer_data(const struct buffer *b) {
    return b->buf;
}

/* Returns the size of the data currently stored in the buffer. */
static inline size_t
buffer_data_len(const struct buffer *b) {
    return b->data_len;
}

/* Returns a pointer to the unused part of the buffer. */
static inline uint8_t *
buffer_tail(const struct buffer *b) {
    return b->buf + b->data_len;
}

/* Returns the size of the available unused part of the buffer. */
static inline size_t
buffer_tail_len(const struct buffer *b) {
    return b->len - b->data_len;
}

/* Ensures that buffer can store at least that much data. */
static void
buffer_ensurelen(struct buffer *b, size_t len) {
    if (len <= b->len) {
        return;
    }
    b->len = len;
    b->buf = realloc(b->buf, b->len);
}

/* After writing to tail, this notifies the buffer of the
 * new data written. */
static void
buffer_data_write(struct buffer *b, size_t len) {
    assert(b != NULL);
    assert(b->len >= b->data_len + len);

    b->data_len += len;
}

/* After processing the data, this notifies the buffer that
 * some data can be freed up. */
static void
buffer_data_read(struct buffer *b, size_t len) {
    assert(b != NULL);
    assert(b->data_len >= len);

    if (len == b->data_len) {
        b->data_len = 0;
        return;
    }

    memmove(b->buf, b->buf + len, b->data_len - len);
    b->data_len -= len;
}

#endif /* CTRL_CONN_BUFFER_H */
