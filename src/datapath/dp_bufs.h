/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef DP_BUFS_H
#define DP_BUFS_H 1

#include <stddef.h>
#include "lib/openflow.h"


struct dp_loop;
struct dp_bufs;
struct pkt_buf;

struct dp_bufs *
dp_bufs_new(struct dp_loop *dp_loop);

size_t
dp_bufs_size(struct dp_bufs *bufs);

of_bufferid_t
dp_bufs_put(struct dp_bufs *bufs, struct pkt_buf *pkt);

of_bufferid_t
dp_bufs_put_raw(struct dp_bufs *bufs, uint8_t *raw, size_t raw_len);

struct pkt_buf *
dp_bufs_get(struct dp_bufs *bufs, of_bufferid_t id);

bool
dp_bufs_alive(struct dp_bufs *bufs, of_bufferid_t id);

void
dp_bufs_discard(struct dp_bufs *bufs, of_bufferid_t id, bool destroy);


#endif /* DP_BUFS_H */
