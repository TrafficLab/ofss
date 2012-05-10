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
 * Code handling buffers used by the pipeline, when sending packet-in messages.
 */

#include <ev.h>
#include <uthash/utlist.h>
#include "logger/logger.h"
#include "logger/logger_mgr.h"
#include "lib/compiler.h"
#include "lib/openflow.h"
#include "lib/logger_names.h"
#include "lib/pkt_buf.h"
#include "dp.h"
#include "dp_bufs.h"


/* NOTE: buffer id is structured as:
 * bit 0       : always zero (so that ffff...ffff never happens)
 * bit 1 - n-1 : guard (incremented at every put, to guard from requesting expired buffers)
 * bit n - 31  : internal buffer id
 */

#define BUFS_BITS    12
#define BUFS_NUM     (1 << BUFS_BITS)
#define GUARD_BITS   (31 - BUFS_BITS)

#define ID_MASK      ((1 << BUFS_BITS) - 1)
#define GUARD_MASK   (((1 << GUARD_BITS) - 1) << BUFS_BITS)

#define TIMEOUT      1.0

struct buffer {
    of_bufferid_t    id;
    ev_tstamp        tstamp;
    struct pkt_buf  *pkt;

    struct buffer   *prev;
    struct buffer   *next;
};

struct dp_bufs {
    struct dp_loop    *dp_loop;
    struct logger     *logger;
    struct buffer     *used;
    struct buffer     *unused;
    struct buffer     *bufs[BUFS_NUM];
};

/* creates a new DP buffer entity (which holds the buffers). */
struct dp_bufs * MALLOC_ATTR
dp_bufs_new(struct dp_loop *dp_loop) {
    struct dp_bufs *bufs = malloc(sizeof(struct dp_bufs));
    bufs->dp_loop = dp_loop;
    bufs->logger = logger_mgr_get(LOGGER_NAME_DP_BUFS, dp_loop_get_uid(dp_loop));
    bufs->used = NULL;
    bufs->unused = NULL;

    size_t i;
    for (i=0; i < BUFS_NUM; i++) {
        struct buffer *buf = malloc(sizeof(struct buffer));
        buf->id = (GUARD_MASK & 0xffffffff) | (ID_MASK & i); // guard will start on all f
        buf->pkt = NULL;

        DL_APPEND(bufs->unused, buf);
        bufs->bufs[i] = buf;
    }

    logger_log(bufs->logger, LOG_DEBUG, "Initialized.");
    return bufs;
}

/* Returns the total number of buffers. */
size_t
dp_bufs_size(struct dp_bufs *bufs UNUSED_ATTR) {
    return BUFS_NUM;
}

/* Increases the guard value of the given buffer entry. */
inline void
inc_guard(struct buffer *buf) {
    size_t guard = (buf->id & GUARD_MASK) >> BUFS_BITS;
    guard++;
    buf->id = (buf->id & !GUARD_MASK) | ((guard << BUFS_BITS) & GUARD_MASK);
}

/* Puts the packet to the buffer. Returns the buffer_id associated with the
 * buffer entry storing the packet. */
of_bufferid_t
dp_bufs_put(struct dp_bufs *bufs, struct pkt_buf *pkt) {
    ev_tstamp now = dp_loop_now(bufs->dp_loop);

    if (bufs->unused != NULL) {
        // there was an unused node
        struct buffer *buf = bufs->unused;
        inc_guard(buf);
        buf->pkt = pkt;
        buf->tstamp = now;

        DL_DELETE(bufs->unused, buf);
        DL_APPEND(bufs->used, buf);

        return buf->id;
    }

    // there was no unused node
    struct buffer *buf = bufs->used;
    assert(buf != NULL);

    if (buf->tstamp - now + TIMEOUT < 0) {
        // the buffer is timed out, reuse it
        pkt_buf_free(buf->pkt);

        inc_guard(buf);
        buf->pkt    = pkt;
        buf->tstamp = now;

        // move to end of used list
        DL_DELETE(bufs->used, buf);
        DL_APPEND(bufs->used, buf);

        return buf->id;
    }

    // there is no free buffer at the moment
    return OF_NO_BUFFER;
}

/* Puts the packet to the buffer. Returns the buffer_id associated with the
 * buffer entry storing the packet. */
of_bufferid_t
dp_bufs_put_raw(struct dp_bufs *bufs, uint8_t *raw, size_t raw_len) {
    ev_tstamp now = dp_loop_now(bufs->dp_loop);

    if (bufs->unused != NULL) {
        // there was an unused node
        struct buffer *buf = bufs->unused;
        inc_guard(buf);
        buf->pkt = pkt_buf_new_use(raw, raw_len);
        buf->tstamp = now;

        DL_DELETE(bufs->unused, buf);
        DL_APPEND(bufs->used, buf);

        return buf->id;
    }

    // there was no unused node
    struct buffer *buf = bufs->used;
    assert(buf != NULL);

    if (buf->tstamp - now + TIMEOUT < 0) {
        // the buffer is timed out, reuse it
        pkt_buf_free(buf->pkt);

        inc_guard(buf);
        buf->pkt    = pkt_buf_new_use(raw, raw_len);
        buf->tstamp = now;

        // move to end of used list
        DL_DELETE(bufs->used, buf);
        DL_APPEND(bufs->used, buf);

        return buf->id;
    }

    // there is no free buffer at the moment
    return OF_NO_BUFFER;
}


/* Retrieves the packet from the buffer and frees the buffer. */
// NOTE: assumes buffer is only read once
struct pkt_buf *
dp_bufs_get(struct dp_bufs *bufs, of_bufferid_t id) {
    struct buffer *buf = bufs->bufs[id & ID_MASK];
    assert(buf != NULL);
    if (buf->pkt == NULL) {
        // requested buffer is unused
        return NULL;
    }

    if ((id & GUARD_MASK) != (buf->id & GUARD_MASK)) {
        // requested buffer has wrong guard
        logger_log(bufs->logger, LOG_DEBUG, "buffer guard mismatch: %x != %x.\n",
                                                         id, buf->id);
        return NULL;
    }

    // free node
    struct pkt_buf *pkt = buf->pkt;
    buf->pkt = NULL;
    DL_DELETE(bufs->used, buf);
    DL_APPEND(bufs->unused, buf);

    return pkt;
}

/* Tells whether the given buffer entry stores a packet (not timed out). */
bool
dp_bufs_alive(struct dp_bufs *bufs, of_bufferid_t id) {
    // assert node is not null
    struct buffer *buf = bufs->bufs[id & ID_MASK];
    assert(buf != NULL);

    if (buf->pkt == NULL) {
        // requested buffer is unused
        return false;
    }

    if ((id & GUARD_MASK) != (buf->id & GUARD_MASK)) {
        // requested buffer has wrong guard
        return false;
    }

    return (buf->tstamp - dp_loop_now(bufs->dp_loop) + TIMEOUT > 0);
}

/* Discards a packet in a buffer entry. Tells whether the packet
 * should be discarded as well. */
void
dp_bufs_discard(struct dp_bufs *bufs, of_bufferid_t id, bool destroy) {
    struct buffer *buf = bufs->bufs[id & ID_MASK];
    assert(buf != NULL);

    if (buf->pkt == NULL) {
        // requested buffer is unused
        return;
    }

    if ((id & GUARD_MASK) != (buf->id & GUARD_MASK)) {
        // requested buffer has wrong guard
        return;
    }

    // free node
    if (destroy) {
        pkt_buf_free(buf->pkt);
    }
    buf->pkt = NULL;
    DL_DELETE(bufs->used, buf);
    DL_APPEND(bufs->unused, buf);
}

