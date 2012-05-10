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
 * Code for parsing DP configuration related command line arguments.
 */

#include <argp.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <uthash/utlist.h>
#include "lib/compiler.h"
#include "lib/openflow.h"
#include "conf_args.h"
#include "conf_int.h"

void * MALLOC_ATTR
conf_args_new() {
    struct conf_args *args = malloc(sizeof(struct conf_args));
    args->dp = malloc(sizeof(struct dp_args));
    args->dp->dpid = OF_NO_DPID;
    args->ctrls = NULL;
    args->ports = NULL;

    return args;
}

void
conf_args_free(void *args_) {
    assert(args_ != NULL);
    struct conf_args *args = (struct conf_args *)args_;

    free(args->dp);

    struct ctrl_arg *ctrl, *cnext;
    LL_FOREACH_SAFE(args->ctrls, ctrl, cnext) {
        free(ctrl->transport);
        free(ctrl->host);
        free(ctrl->port);
        free(ctrl);
    }

    struct port_arg *port, *pnext;
    LL_FOREACH_SAFE(args->ports, port, pnext) {
        free(port->driver_name);
        free(port->port_name);
        free(port);
    }

    free(args);
}


void
conf_args_parse_dp(void *args_, char *arg, struct argp_state *state) {
    assert(args_ != NULL);
    struct conf_args *args = (struct conf_args *)args_;

    // tokenize on separators
    char *dp, *save_ptr;
    for (dp = strtok_r(arg, ",", &save_ptr); dp != NULL; dp = strtok_r(NULL, ",", &save_ptr)) {
        // check if port has a colon
        char *colon = strchr(dp, ':');

        if (colon == NULL) {
            argp_error(state, "Unable to parse argument: %s.", dp);
        }

        if (strncmp("dpid", dp, colon - dp) == 0) {
            // checking the dpid
            if (strlen(colon + 1) > 16 || strspn(colon + 1, "0123456789abcdefABCDEF") != strlen(colon + 1)) {
                argp_error(state, "Unable to parse dpid: %s.", dp);
            }
            if (sscanf(colon + 1, "%"SCNx64"", &(args->dp->dpid)) != 1) {
                argp_error(state, "Unable to parse dpid: %s.", dp);
            }
            if (args->dp->dpid == 0) {
                argp_error(state, "Dpid must not be zero: %s.", dp);
            }
        } else {
            argp_error(state, "Unable to parse argument: %s.", dp);
        }
    }
}

void
conf_args_parse_ctrls(void *args_, char *arg, struct argp_state *state){
    assert(args_ != NULL);
    struct conf_args *args = (struct conf_args *)args_;

    // tokenize on separators
    char *ctrl, *save_ptr;
    for (ctrl = strtok_r(arg, ",", &save_ptr); ctrl != NULL;
         ctrl = strtok_r(NULL, ",", &save_ptr)) {

        struct ctrl_arg *ca = malloc(sizeof(struct ctrl_arg));

        // check if port has a colon
        char *colon = strchr(ctrl, ':');

        if (colon == NULL) {
            // default transport and port
            ca->transport = NULL;
            ca->host  = strdup(ctrl);
            ca->port  = NULL;
        } else {
            char *colon2 = strchr(colon + 1, ':');

            if (colon2 == NULL) {
                // ctrl is host:port
                uint16_t port;
                if (sscanf(colon + 1, "%"SCNu16"", &port) != 1) {
                    argp_error(state, "Port must be a number: %s.", ctrl);
                }

                ca->transport = NULL;
                ca->host  = strncpy(malloc(colon - ctrl + 1), ctrl, colon - ctrl);
                ca->host[colon - ctrl] = '\0';
                ca->port  = strdup(colon2 + 1);
            } else {
                // ctrl is transp:host:port
                uint16_t port;

                if (sscanf(colon2 + 1, "%"SCNu16"", &port) != 1) {
                    argp_error(state, "Port must be a number: %s.", ctrl);
                }

                ca->transport = strncpy(malloc(colon - ctrl + 1), ctrl, colon - ctrl);
                ca->transport[colon - ctrl] = '\0';
                ca->host  = strncpy(malloc(colon2 - colon + 1), colon + 1, colon2 - colon - 1);
                ca->host[colon2 - colon] = '\0';
                ca->port  = strcpy(malloc(strlen(colon2 + 1) + 1), colon2 + 1);
            }
        }
        LL_APPEND(args->ctrls, ca);
    }
}

void
conf_args_parse_ports(void *args_, char *arg, struct argp_state *state UNUSED_ATTR) {
    assert(args_ != NULL);
    struct conf_args *args = (struct conf_args *)args_;

    // tokenize on separators
    char *port, *save_ptr;
    for (port = strtok_r(arg, ",", &save_ptr); port != NULL;
            port = strtok_r(NULL, ",", &save_ptr)) {

        struct port_arg *pa = malloc(sizeof(struct port_arg));

        // check if port has a colon
        char *colon = strchr(port, ':');

        if (colon == NULL) {
            // default driver
            pa->driver_name = NULL;
            pa->port_name   = strdup(port);
        } else {
            // port is driver_name:port_name
            pa->driver_name = strncpy(malloc(colon - port + 1), port, colon - port);
            pa->driver_name[colon-port] = '\0';
            pa->port_name   = strdup(colon + 1);  // skip the colon
        }
        LL_APPEND(args->ports, pa);
    }
}
