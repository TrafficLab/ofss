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
 * PCAP driver.
 */

#include <assert.h>
#include <stdlib.h>
#include <ev.h>
#include <pthread.h>
#include <pcap.h>
#include "lib/compiler.h"
#include "lib/message_box.h"
#include "lib/pkt_buf.h"
#include "lib/thread_id.h"
#include "lib/logger_names.h"
#include "logger/logger.h"
#include "logger/logger_mgr.h"
#include "pcap_drv.h"
#include "pcap_drv_int.h"
#include "pcap_port.h"


static bool event_loop_pkt_out_cb(void *pcap_port_, struct list_node *pkt_in_);

static void *event_loop(void *pcap_drv_loop_);

/* Static initializer for the driver. */
struct pcap_drv * MALLOC_ATTR
pcap_drv_init(struct port_drv *drv) {
    struct pcap_drv *pcap_drv = malloc(sizeof(struct pcap_drv));
    pcap_drv->drv = drv;
    pcap_drv->logger = logger_mgr_get(LOGGER_NAME_PORT_DRV_PCAP);

    pcap_drv->ports_map = NULL;
    size_t i;
    for (i=0; i<MAX_PORTS; i++) {
        pcap_drv->ports[i] = NULL;
    }
    pcap_drv->ports_num = 0;

    pcap_drv->ports_rwlock = malloc(sizeof(pthread_rwlock_t));
    pthread_rwlock_init(pcap_drv->ports_rwlock, NULL);

    struct pcap_drv_loop *pcap_drv_loop = malloc(sizeof(struct pcap_drv_loop));
    pcap_drv_loop->logger = logger_mgr_get(LOGGER_NAME_PORT_DRV_PCAP_IF);

    pcap_drv->pcap_drv_loop = pcap_drv_loop;
    pcap_drv_loop->pcap_drv = pcap_drv;

    pcap_drv->thread = malloc(sizeof(pthread_t));
    pcap_drv->loop = ev_loop_new(0/*flags*/);
    pcap_drv_loop->loop = pcap_drv->loop;

    ev_set_userdata(pcap_drv->loop, (void *)pcap_drv_loop);

    pcap_drv->notifier = mbox_new(pcap_drv->loop, NULL, NULL);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    int rc;
    if ((rc = pthread_create(pcap_drv->thread, &attr, event_loop, (void *)pcap_drv_loop)) != 0) {
        logger_log(pcap_drv->logger, LOG_ERR, "Unable to create thread (%d).", rc);
        //TODO: free structures
        return NULL;
    }

    logger_log(pcap_drv->logger, LOG_INFO, "PCAP initialized.");

    return pcap_drv;
}

/* Opens a port with the driver. */
static ssize_t
open_port(struct pcap_drv *pcap_drv, const char *name) {
    pthread_rwlock_wrlock(pcap_drv->ports_rwlock);
    // double check the port was not created b/w the calls
    struct pcap_port *port;
    HASH_FIND_STR(pcap_drv->ports_map, name, port);
    if (port != NULL) {
        pthread_rwlock_unlock(pcap_drv->ports_rwlock);
        return port->id;
    }

    if (pcap_drv->ports_num >= MAX_PORTS) {
        logger_log(pcap_drv->logger, LOG_ERR, "Cannot open more ports.");
        pthread_rwlock_unlock(pcap_drv->ports_rwlock);
        return -1;
    }

    port = pcap_port_open(pcap_drv, pcap_drv->ports_num, name);

    if (port != NULL) {
        pcap_drv->ports[pcap_drv->ports_num] = port;
        pcap_drv->ports_num++;
        HASH_ADD_KEYPTR(hh, pcap_drv->ports_map, port->name, strlen(port->name), port);

        pthread_rwlock_unlock(pcap_drv->ports_rwlock);
        return port->id;
    } else {
        pthread_rwlock_unlock(pcap_drv->ports_rwlock);
        return -1;
    }
}

/* Returns an opened port's uid by name. */
ssize_t
pcap_drv_get_port(struct pcap_drv *pcap_drv, const char *name) {
    pthread_rwlock_rdlock(pcap_drv->ports_rwlock);
    struct pcap_port *port;
    HASH_FIND_STR(pcap_drv->ports_map, name, port);
    pthread_rwlock_unlock(pcap_drv->ports_rwlock);

    if (port != NULL) {
        return port->id;
    }

    return open_port(pcap_drv, name);
}


/* Assigns a DP (uid) and its port to the given PCAP port. */
bool
pcap_drv_assign_dp_port(struct pcap_drv *drv, size_t drv_port_no, size_t dp_uid, of_port_no_t dp_port_no) {
    pthread_rwlock_wrlock(drv->ports_rwlock);

    if (drv->ports[drv_port_no] == NULL) {
        pthread_rwlock_unlock(drv->ports_rwlock);
        return false;
    }

    pthread_rwlock_unlock(drv->ports_rwlock);
    struct pcap_port *pcap_port = drv->ports[drv_port_no];

    pthread_rwlock_wrlock(pcap_port->rwlock);

    if (pcap_port->dp_port_no != OF_NO_PORT) {
        // dp port already assigned
        pthread_rwlock_unlock(pcap_port->rwlock);
        pthread_rwlock_unlock(drv->ports_rwlock);
        return false;
    }


    pcap_port->dp_uid = dp_uid;
    pcap_port->dp_port_no = dp_port_no;
    pcap_port->of_port->port_no = dp_port_no;
    pcap_port->of_stats->port_no = dp_port_no;

    pcap_port->pkt_mbox = mbox_new(drv->loop, pcap_port, event_loop_pkt_out_cb);

    ev_io_start(drv->loop, pcap_port->watcher);
    pthread_rwlock_unlock(pcap_port->rwlock);

    mbox_notify(drv->notifier); // needed for io watcher update on loop
    return true;
}

/* Event loop callback for outgoing packets. */
static bool
event_loop_pkt_out_cb(void *pcap_port_, struct list_node *pkt_buf_) {
    struct pcap_port *pcap_port = (struct pcap_port *)pcap_port_;
    struct pkt_buf *pkt_buf = (struct pkt_buf *)pkt_buf_;

    int ret = pcap_inject(pcap_port->pcap, pkt_buf->data, pkt_buf->data_len);
    if (ret == -1) {
        logger_log(pcap_port->logger, LOG_WARN, "Error in pcap_inject: %s.", pcap_geterr(pcap_port->pcap));

        pthread_mutex_lock(pcap_port->stats_mutex);
        pcap_port->of_stats->tx_dropped++;
        pcap_port->of_stats->tx_errors++;
        pthread_mutex_unlock(pcap_port->stats_mutex);

        pkt_buf_free(pkt_buf);
        //TODO perhaps should buffer for later write
        return false; // wait a little with the next packet
    } else if ((ret - pkt_buf->data_len) != 0) {
        logger_log(pcap_port->logger, LOG_WARN, "Pcap_inject could not send the whole packet: %d (%d).",
                                                           ret, pkt_buf->data_len);
        pthread_mutex_lock(pcap_port->stats_mutex);
        pcap_port->of_stats->tx_dropped++;
        pcap_port->of_stats->tx_errors++;
        pthread_mutex_unlock(pcap_port->stats_mutex);

        pkt_buf_free(pkt_buf);
        return false; // wait a little with the next packet
    } else {
        logger_log(pcap_port->logger, LOG_DEBUG, "Sent packet of length %d.", pkt_buf->data_len);
        pthread_mutex_lock(pcap_port->stats_mutex);
        pcap_port->of_stats->tx_bytes += pkt_buf->data_len;
        pcap_port->of_stats->tx_packets++;
        pthread_mutex_unlock(pcap_port->stats_mutex);

        pkt_buf_free(pkt_buf);
        return true;
    }
}

/* The driver's event loop. */
static void *event_loop(void *pcap_drv_loop_) {
    assert(pcap_drv_loop_ != NULL);
    struct pcap_drv_loop *pcap_drv_loop = (struct pcap_drv_loop *)pcap_drv_loop_;

    thread_id_set();

    logger_log(pcap_drv_loop->logger, LOG_INFO, "Thread started for PCAP.");

    ev_ref(pcap_drv_loop->loop); //makes sure an empty loop stays alive
    ev_run(pcap_drv_loop->loop, 0/*flags*/);

    logger_log(pcap_drv_loop->logger, LOG_ERR, "Loop exited.");

    pthread_exit(NULL);
    return NULL;
}

/* Sends a packet on the driver's given port.
 * Can be used by other threads. */
bool
pcap_drv_send_pkt(struct pcap_drv *drv, size_t drv_port_no, struct pkt_buf *pkt_buf) {
    pthread_rwlock_rdlock(drv->ports_rwlock);
    struct pcap_port *port = drv->ports[drv_port_no];
    pthread_rwlock_unlock(drv->ports_rwlock);

    if (port != NULL) {
        mbox_send(port->pkt_mbox, (struct list_node *)pkt_buf); //TODO limit?
        return true;
    } else {
        return false;
    }
}

/* Returns a copy of the port's description. */
struct ofl_port * MALLOC_ATTR
pcap_drv_get_port_desc(struct pcap_drv *drv, size_t drv_port_no) {
    pthread_rwlock_rdlock(drv->ports_rwlock);
    struct pcap_port *port = drv->ports[drv_port_no];
    pthread_rwlock_unlock(drv->ports_rwlock);

    if (port != NULL) {
        pthread_mutex_lock(port->stats_mutex);
        struct ofl_port *ret = memcpy(malloc(sizeof(struct ofl_port)), port->of_port, sizeof(struct ofl_port));
        ret->name = strdup(port->of_port->name);
        pthread_mutex_unlock(port->stats_mutex);
        return ret;
    } else {
        return NULL;
    }
}

/* Returns a copy of the port's statistics description. */
struct ofl_port_stats * MALLOC_ATTR
pcap_drv_get_port_stats(struct pcap_drv *drv, size_t drv_port_no) {
    pthread_rwlock_rdlock(drv->ports_rwlock);
    struct pcap_port *port = drv->ports[drv_port_no];
    pthread_rwlock_unlock(drv->ports_rwlock);

    if (port != NULL) {
        pthread_mutex_lock(port->stats_mutex);
        struct ofl_port_stats *ret = memcpy(malloc(sizeof(struct ofl_port_stats)), port->of_stats, sizeof(struct ofl_port_stats));
        pthread_mutex_unlock(port->stats_mutex);
        return ret;
    } else {
        return NULL;
    }
}

/* Returns a reference to the port's HW address. */
const uint8_t *
pcap_drv_get_port_addr(struct pcap_drv *drv, size_t drv_port_no) {
    pthread_rwlock_rdlock(drv->ports_rwlock);
    struct pcap_port *port = drv->ports[drv_port_no];
    pthread_rwlock_unlock(drv->ports_rwlock);

    if (port != NULL) {
        //TODO: need lock?
        return port->of_port->hw_addr;
    } else {
        return NULL;
    }
}

/* Updates OpenFlow port config of the port. */
void
pcap_drv_port_mod(struct pcap_drv *drv, size_t drv_port_no, uint32_t config) {
    pthread_rwlock_rdlock(drv->ports_rwlock);
    struct pcap_port *port = drv->ports[drv_port_no];
    pthread_rwlock_unlock(drv->ports_rwlock);

    if (port != NULL) {
        pthread_mutex_lock(port->stats_mutex);
        port->of_port->config = config;
        pthread_mutex_unlock(port->stats_mutex);
    } else {
    }
}
