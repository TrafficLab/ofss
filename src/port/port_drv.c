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
 * Port driver handler. Dispatches requests to the actual drivers.
 */

#include <stddef.h>
#include <stdlib.h>
#include "lib/compiler.h"
#include "lib/logger_names.h"
#include "logger/logger.h"
#include "logger/logger_mgr.h"
#include "port_drv.h"
#include "pcap/pcap_drv.h"

/* Initializes the port drivers. */
struct port_drv * MALLOC_ATTR
port_drv_init(enum port_drv_type type) {
    switch (type) {
        case PORT_DRV_PCAP: {
            struct port_drv *drv = malloc(sizeof(struct port_drv));
            drv->type = type;
            drv->logger = logger_mgr_get(LOGGER_NAME_PORT_DRV, PCAP_DRIVER_NAME);
            drv->name = PCAP_DRIVER_NAME;
            void *pcap_drv = pcap_drv_init(drv);
            if (pcap_drv != NULL) {
                drv->private = pcap_drv;
                logger_log(drv->logger, LOG_INFO, "Initialized.");
                return drv;
            } else {
                logger_log(drv->logger, LOG_ERR, "Initialization failed.");
                free(drv);
                return NULL;
            }
        }
        default: {
            return NULL;
        }
    }
}

/* Returns the uid of the driver's port by its name. */
ssize_t
port_drv_get_port(struct port_drv *drv, const char *name) {
    switch (drv->type) {
        case PORT_DRV_PCAP: {
            return pcap_drv_get_port(drv->private, name);
        }
        default: {
            logger_log(drv->logger, LOG_ERR, "Unknown port driver type: %u.", drv->type);
            return -1;
        }
    }
}

/* Assigns a DP and a DP port to the driver's port. */
bool
port_drv_assign_dp_port(struct port_drv *drv, size_t drv_port_no, size_t dp_uid, of_port_no_t dp_port_no) {
    switch (drv->type) {
        case PORT_DRV_PCAP: {
            return pcap_drv_assign_dp_port(drv->private, drv_port_no, dp_uid, dp_port_no);
        }
        default: {
            logger_log(drv->logger, LOG_ERR, "Unknown port driver type: %u.", drv->type);
            return false;
        }
    }
}

/* Sends a packet out on the given port. */
bool
port_drv_send_pkt(struct port_drv *drv, size_t drv_port_no, struct pkt_buf *pkt_buf) {
    switch (drv->type) {
        case PORT_DRV_PCAP: {
            return pcap_drv_send_pkt(drv->private, drv_port_no, pkt_buf);
        }
        default: {
            logger_log(drv->logger, LOG_ERR, "Unknown port driver type: %u.", drv->type);
            return false;
        }
    }
}

/* Returns a copy of the port's description. */
struct ofl_port *
port_drv_get_port_desc(struct port_drv *drv, size_t drv_port_no){
    switch (drv->type) {
        case PORT_DRV_PCAP: {
            return pcap_drv_get_port_desc(drv->private, drv_port_no);
        }
        default: {
            logger_log(drv->logger, LOG_ERR, "Unknown port driver type: %u.", drv->type);
            return NULL;
        }
    }
}


/* Returns a copy of the port's statistics. */
struct ofl_port_stats *
port_drv_get_port_stats(struct port_drv *drv, size_t drv_port_no) {
    switch (drv->type) {
        case PORT_DRV_PCAP: {
            return pcap_drv_get_port_stats(drv->private, drv_port_no);
        }
        default: {
            logger_log(drv->logger, LOG_ERR, "Unknown port driver type: %u.", drv->type);
            return NULL;
        }
    }
}

/* Returns a reference to the port's hw address. */
const uint8_t *
port_drv_get_port_addr(struct port_drv *drv, size_t drv_port_no) {
    switch (drv->type) {
        case PORT_DRV_PCAP: {
            return pcap_drv_get_port_addr(drv->private, drv_port_no);
        }
        default: {
            logger_log(drv->logger, LOG_ERR, "Unknown port driver type: %u.", drv->type);
            return NULL;
        }
    }
}

/* Updates OpenFlow port config of the port. */
void
port_drv_port_mod(struct port_drv *drv, size_t drv_port_no, uint32_t config) {
    switch (drv->type) {
        case PORT_DRV_PCAP: {
            pcap_drv_port_mod(drv->private, drv_port_no, config);
            return;
        }
        default: {
            logger_log(drv->logger, LOG_ERR, "Unknown port driver type: %u.", drv->type);
            return;
        }
    }
}

/* Returns the name of the port. */
const char *
port_drv_get_name(struct port_drv *drv) {
    return drv->name;
}
