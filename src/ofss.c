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
 * The main ofss executabe.
 */

#include <argp.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include "config/conf.h"
#include "config/conf_args.h"
#include "datapath/dp_mgr.h"
#include "logger/logger_args.h"
#include "logger/logger_mgr.h"
#include "lib/info.h"
#include "lib/thread_id.h"
#include "port/port_drv_mgr.h"


struct conf;

struct args {
    void  *config;
    void  *logger;
    bool   show_info;
};

static struct argp argp;
int main(int argc, char *argv[]) {

    struct args args = {
                .config    = conf_args_new(),
                .logger    = logger_args_new(),
                .show_info = false
            };

    // this call will exit on any argument error (see argp_error).
    if (argp_parse(&argp, argc, argv, 0/*flags*/, 0/*arg_index*/, &args) != 0) {
        printf("Error parsing the arguments.");
        return -1;
    }

    // static initialization of modules
    logger_mgr_init();
    thread_id_init();
    port_drv_mgr_init();
    dp_mgr_init();
    conf_init();

    logger_mgr_args(args.logger);

    // create DP from parsed command line args
    conf_args(args.config);

    logger_args_free(args.logger);
    conf_args_free(args.config);

    // wait for all threads to exit before exiting
    pthread_exit(NULL);
}

/*
 * Processing the command line arguments (see argp)
 */

/* these values are fed in by autotools */
const char *argp_program_version = PACKAGE_VERSION;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

/* the description of the different options */
static struct argp_option argp_options[] = {
    LOGGER_ARGS,
    CONF_ARGS,
    INFO_ARGS
};


/* Function for parsing command line arguments. Calls the appropriate
 * callback for each module. */
static error_t
argp_parser(int key, char *arg, struct argp_state *state) {
    struct args *args = (struct args *)(state->input);

    switch (key) {
        case CONF_DP_ARGS_KEY: {
            conf_args_parse_dp(args->config, arg, state);
            break;
        }
        case CONF_CTRLS_ARGS_KEY: {
            conf_args_parse_ctrls(args->config, arg, state);
            break;
        }
        case CONF_PORTS_ARGS_KEY: {
            conf_args_parse_ports(args->config, arg, state);
            break;
        }
        case LOGGER_ARGS_KEY: {
            logger_args_parse(args->logger, arg, state);
            break;
        }
        case INFO_ARGS_KEY: {
            args->show_info = true;
            break;
        }
        case ARGP_KEY_ARG: {
            // skip arguments
            break;
        }
        case ARGP_KEY_END: {
            // all arguments are processed;
            if (args->show_info) {
                info();
            }
            break;
        }
        default: {
            return ARGP_ERR_UNKNOWN;
        }
    }

    return 0;
}

static struct argp argp = {
    .options  = argp_options,
    .parser   = argp_parser,
    .args_doc = "",  // only options, but no arguments
    .doc      = "ofss -- An OpenFlow software switch implementation from TrafficLab, Ericsson Research, Hungary."
};
