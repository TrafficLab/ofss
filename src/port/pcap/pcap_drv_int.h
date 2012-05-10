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
 * Common internal structures for the PCAP driver.
 */

#ifndef PCAP_DRV_INT_H
#define PCAP_DRV_INT_H 1

#include <ev.h>
#include <pthread.h>
#include <pcap.h>
#include <uthash/uthash.h>
#include "lib/message_box.h"
#include "lib/openflow.h"
#include "oflib/ofl_structs.h"

#define MAX_PORTS   16

struct pcap_port {
    struct pcap_drv       *drv;
    size_t                 id;
    char                  *name;
    struct logger         *logger;

    pcap_t                *pcap;
    int                    fd;
    ev_io                  *watcher;

    size_t                  dp_uid;
    of_port_no_t            dp_port_no;
    struct mbox            *pkt_mbox;
    pthread_rwlock_t       *rwlock;

    struct ofl_port        *of_port;
    struct ofl_port_stats  *of_stats;
    pthread_mutex_t        *stats_mutex;

    UT_hash_handle   hh;
};


struct pcap_drv {
    struct port_drv  *drv;

    struct logger   *logger;

    pthread_t        *thread;
    struct ev_loop   *loop;

    struct pcap_port  *ports_map;
    struct pcap_port  *ports[MAX_PORTS];
    size_t             ports_num;
    pthread_rwlock_t  *ports_rwlock;

    struct mbox       *notifier;

    struct pcap_drv_loop  *pcap_drv_loop;
};

struct pcap_drv_loop {
    struct logger   *logger;

    struct ev_loop   *loop;

    struct pcap_drv  *pcap_drv;
};


void pcap_port_fill(struct pcap_port *pcap_port);


#endif /* PCAP_DRV_INT_H */
