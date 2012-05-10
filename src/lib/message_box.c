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
 * A message box implements the communication between two threads.
 * A sender thread can send an opaque (list-like element) to the
 * receiver thread.
 */
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <ev.h>
#include <pthread.h>
#include <uthash/utlist.h>
#include "lib/compiler.h"
#include "lib/list.h"
#include "message_box.h"

struct mbox {
    struct ev_loop   *loop;
    struct ev_async  *watcher;
    struct list_node      *queue;
    size_t            queue_len;
    pthread_mutex_t  *mutex;
    mbox_cb_t         callback;
    void             *private;
};


/* Internal callback called by the event handler when a message arrived.
 * Dispactches it (or them) to the given callback. */
static void
callback(struct ev_loop *loop UNUSED_ATTR, ev_async *w, int revents UNUSED_ATTR) {
    struct mbox *mbox = (struct mbox *)(w->data);

    pthread_mutex_lock(mbox->mutex);

    if (mbox->queue_len == 0) {
        //mbox was used for notifying the loop only
        assert(mbox->queue == NULL);
        pthread_mutex_unlock(mbox->mutex);
        return;
    }

    // process messages in the queue now, but not those
    // added while processing
    size_t queue_len = mbox->queue_len;
    bool cont = true;

    do {
        assert(mbox->queue != NULL);
        struct list_node *msg = mbox->queue;
        DL_DELETE(mbox->queue, msg);
        mbox->queue_len--;
        queue_len--;

        pthread_mutex_unlock(mbox->mutex);
        cont = (mbox->callback)(mbox->private, msg);
        if (!cont || (queue_len == 0)) {
            break;
        }
        pthread_mutex_lock(mbox->mutex);
    } while (true);

    if (queue_len > 0) {
        // remaining items, notify again
        ev_async_send(loop, w);
    }
}

/* Creates a new message box on the given event loop. */
struct mbox * MALLOC_ATTR
mbox_new(struct ev_loop *loop, void *private, mbox_cb_t cb) {
    struct mbox *mbox = malloc(sizeof(struct mbox));
    mbox->loop      = loop;
    mbox->watcher   = malloc(sizeof(struct ev_async));
    mbox->queue     = NULL;
    mbox->queue_len = 0;
    mbox->mutex     = malloc(sizeof(pthread_mutex_t));
    mbox->callback  = cb;
    mbox->private   = private;

    mbox->watcher->data = mbox;
    ev_async_init(mbox->watcher, callback);
    ev_async_start(loop, mbox->watcher);

    pthread_mutex_init(mbox->mutex, NULL);
    return mbox;
}

/* Notifies the event loop of something. Essentially equals
 * to sending an empty message.
 * NOTE: Sometimes the underlying event-loop needs to be triggered
 * for some internal updates; e.g. when adding new watchers.
 */
void
mbox_notify(struct mbox *mbox) {
    ev_async_send(mbox->loop, mbox->watcher);
}

/* Send a message over the message box. */
void
mbox_send(struct mbox *mbox, struct list_node *msg) {
    pthread_mutex_lock(mbox->mutex);
    DL_APPEND(mbox->queue, msg);
    mbox->queue_len++;
    pthread_mutex_unlock(mbox->mutex);
    ev_async_send(mbox->loop, mbox->watcher);
}

/* Send a message over the message box, if the box is not full yet. */
bool
mbox_send_limit(struct mbox *mbox, struct list_node *msg, size_t queue_len) {
    pthread_mutex_lock(mbox->mutex);
    if (mbox->queue_len > queue_len) {
        pthread_mutex_unlock(mbox->mutex);
        return false;
    }
    DL_APPEND(mbox->queue, msg);
    mbox->queue_len++;
    pthread_mutex_unlock(mbox->mutex);
    ev_async_send(mbox->loop, mbox->watcher);
    return true;
}
