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
 * The DP Manager holds references to the spawned DPs.
 * It allows other modules to send messages to DP's by using their
 * unique IDs (so they don't need to have an actual pointer to the
 * DP structure.
 */
#include <inttypes.h>
#include <stdlib.h>
#include <pthread.h>
#include "lib/compiler.h"
#include "lib/openflow.h"
#include "lib/logger_names.h"
#include "logger/logger.h"
#include "logger/logger_mgr.h"
#include "dp.h"
#include "dp_int.h"

#define MAX_DPS   16


static struct logger     *logger;
static pthread_rwlock_t  *rwlock;
static struct dp         *dps[MAX_DPS];
static size_t             dps_num;


static of_dpid_t random_dpid();

/* Static initializer. */
void dp_mgr_init() {
    logger = logger_mgr_get(LOGGER_NAME_DP_MANAGER);
    rwlock = malloc(sizeof(pthread_rwlock_t));
    pthread_rwlock_init(rwlock, NULL);

    size_t i;
    for (i=0; i<MAX_DPS; i++) {
        dps[i] = NULL;
    }
    dps_num = 0;
}

/* Spawns a new Datapath. Returns its unique ID. */
ssize_t
dp_mgr_create_dp(of_dpid_t dpid) {
    pthread_rwlock_wrlock(rwlock);

    if (dps_num == MAX_DPS) {
        pthread_rwlock_unlock(rwlock);
        return -1;
    }

    if (dpid != OF_NO_DPID) {
        size_t i;
        for (i=0; i < dps_num; i++) {
            if (dps[i]->dpid == dpid) {
                logger_log(logger, LOG_ERR, "Request for new datapath with existing dpid: %"PRIx64".", dpid);
                pthread_rwlock_unlock(rwlock);
                return -1;
            }
        }
    } else {
        dpid = random_dpid();
    }

    ssize_t uid = dps_num;
    dps_num++;

    dps[uid] = dp_new(uid, dpid);
    //TODO: check for null
    pthread_rwlock_unlock(rwlock);

    return uid;
}

/* Returns the unique id for the DP with the given DPID. */
ssize_t
dp_mgr_get_uid(of_dpid_t dpid) {
    pthread_rwlock_rdlock(rwlock);
    size_t i;
    for (i=0; i < dps_num; i++) {
        if (dps[i]->dpid == dpid) {
            pthread_rwlock_unlock(rwlock);
            return i;
        }
    }

    pthread_rwlock_unlock(rwlock);
    return -1;
}

/* Returns the DPID of the given DP based on its unique ID. */
of_dpid_t
dp_mgr_get_dpid(size_t dp_uid) {
    pthread_rwlock_rdlock(rwlock);
    struct dp *dp = dps[dp_uid];
    pthread_rwlock_unlock(rwlock);
    if (dp == NULL) {
        return OF_NO_DPID;
    } else {
        return dp->dpid;
    }
}

/* Sends an incoming packet to the given DP. */
void
dp_mgr_dp_recv_pkt(size_t dp_uid, of_port_no_t port_no, struct pkt_buf *pkt_buf) {
    pthread_rwlock_rdlock(rwlock);
    struct dp *dp = dps[dp_uid];
    pthread_rwlock_unlock(rwlock);

    if (dp != NULL) {
        dp_recv_pkt(dp, port_no, pkt_buf);
    } else {
        logger_log(logger, LOG_ERR, "Request for unknown DP: %d.", dp_uid);
    }

}

/* Sends an incoming message to the given DP. */
void
dp_mgr_dp_recv_msg(size_t dp_uid, size_t conn_id, of_xid_t xid, struct ofl_msg_header *msg, uint8_t *of_msg, size_t of_msg_len) {
    pthread_rwlock_rdlock(rwlock);
    struct dp *dp = dps[dp_uid];
    pthread_rwlock_unlock(rwlock);

    if (dp != NULL) {
        dp_recv_msg(dps[dp_uid], conn_id, xid, msg, of_msg, of_msg_len);
    } else {
        logger_log(logger, LOG_ERR, "Request for unknown DP: %d.", dp_uid);
    }
}

/* Sends a request to add a port to the given DP. */
void
dp_mgr_dp_add_port(size_t dp_uid, of_port_no_t port_no, const char *driver, const char *port) {
    pthread_rwlock_rdlock(rwlock);
    struct dp *dp = dps[dp_uid];
    pthread_rwlock_unlock(rwlock);

    if (dp != NULL) {
        dp_add_port(dp, port_no, driver, port);
    } else {
        logger_log(logger, LOG_ERR, "Request for unknown DP: %d.", dp_uid);
    }
}

/* Sends a request to add a controller connection to the given DP. */
void
dp_mgr_dp_add_ctrl(size_t dp_uid, const char *trans, const char *host, const char *port) {
    pthread_rwlock_rdlock(rwlock);
    struct dp *dp = dps[dp_uid];
    pthread_rwlock_unlock(rwlock);

    if (dp != NULL) {
        dp_add_ctrl(dps[dp_uid], trans, host, port);
    } else {
        logger_log(logger, LOG_ERR, "Request for unknown DP: %d.", dp_uid);
    }

}



/* Checks whether the requested (or generated) DPID is not used.
 * NOTE: must be called with rwlock locked. */
static bool
is_dpid_free(of_dpid_t dpid) {
    size_t i;
    for (i=0; i < dps_num; i++) {
        if (dps[i]->dpid == dpid) {
            return false;
        }
    }
    return true;
}

/* Generates a new random DPID. */
static of_dpid_t
random_dpid() {
    of_dpid_t dpid;

    do {
        size_t i;
        for (i = 0; i < 8; i++) {
            *((uint8_t *)&dpid + i) = (uint8_t)random();
        }
    } while (dpid == OF_NO_DPID || !is_dpid_free(dpid));

    return dpid;
}
