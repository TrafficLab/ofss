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
 * Configuration handler.
 * At the moment it only instantiates a single DP based on
 * the command line arguments.
 */

#include <stdlib.h>
#include <uthash/utlist.h>
#include "datapath/dp_mgr.h"
#include "logger/logger.h"
#include "logger/logger_mgr.h"
#include "conf.h"
#include "conf_args.h"
#include "conf_int.h"
#include "lib/logger_names.h"
#include "lib/util.h"


static struct logger *logger;

/* Static initializer for config manager. */
void
conf_init() {
    logger = logger_mgr_get(LOGGER_NAME_CONFIG);
}

/* Processes command line arguments. */
void
conf_args(void *args_) {
    assert(args_ != NULL);
    struct conf_args *args = (struct conf_args *)args_;

    // Create DP
    ssize_t dp_uid = dp_mgr_create_dp(args->dp->dpid);
    if (dp_uid == -1) {
        logger_log(logger, LOG_ERR, "Could not create requested DP.");
        conf_args_free(args);
        return;
	}

	// Add ports
    struct port_arg *port;
    LL_FOREACH(args->ports, port) {
        dp_mgr_dp_add_port(dp_uid, OF_NO_PORT, port->driver_name, port->port_name);
    }

    // Add controllers
    struct ctrl_arg *ctrl;
    LL_FOREACH(args->ctrls, ctrl) {
        dp_mgr_dp_add_ctrl(dp_uid, ctrl->transport, ctrl->host, ctrl->port);
    }

    logger_log(logger, LOG_INFO, "Created new DP (%u) from args.", dp_uid);
}
