/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */


#ifndef MESSAGE_BOX_H
#define MESSAGE_BOX_H 1

#include <ev.h>
#include <stdbool.h>
#include "lib/list.h"

typedef bool (*mbox_cb_t)(void *priv, struct list_node *m);


struct mbox *
mbox_new(struct ev_loop *loop, void *private, mbox_cb_t cb);

void
mbox_notify(struct mbox *mbox);

void
mbox_send(struct mbox *mbox, struct list_node *l);

bool
mbox_send_limit(struct mbox *mbox, struct list_node *l, size_t queue_len);


#endif /* MESSAGE_BOX_H */
