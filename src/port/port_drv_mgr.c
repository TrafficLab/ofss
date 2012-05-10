/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#include <stddef.h>
#include <uthash/uthash.h>
#include "lib/compiler.h"
#include "lib/logger_names.h"
#include "logger/logger.h"
#include "logger/logger_mgr.h"
#include "port_drv.h"
#include "port_drv_int.h"
#include "port_drv_mgr.h"

/* Port driver manager. Upon initialization it starts up the registered port drivers. */


struct port_drv_ent {
    struct port_drv *drv;
    UT_hash_handle hh;
};


static struct logger        *logger;
static struct port_drv_ent  *drivers;


/* Static initializer. */
void
port_drv_mgr_init() {
    logger = logger_mgr_get(LOGGER_NAME_PORT_DRV_MGR);
    drivers = NULL;

    size_t i;
    for (i=0; i < PORT_DRVS_NUM; i++) {
        struct port_drv *port_drv = port_drv_init(i);
        if (port_drv == NULL) {
            logger_log(logger, LOG_ERR, "Error initializing driver %u.", i);
        } else {
            struct port_drv_ent *ent = malloc(sizeof(struct port_drv_ent));
            ent->drv = port_drv;
            HASH_ADD_KEYPTR(hh, drivers, port_drv->name, strlen(port_drv->name), ent);
        }
    }

    logger_log(logger, LOG_INFO, "Initialized.");
}

/* Returns a port driver by name. */
struct port_drv *
port_drv_mgr_get(const char *name) {
    if (name == NULL) { name = DEFAULT_DRIVER_NAME; }

    struct port_drv_ent *ent;
    HASH_FIND_STR(drivers, name, ent);

    if (ent != NULL) {
        return ent->drv;
    } else {
        return NULL;
    }
}
