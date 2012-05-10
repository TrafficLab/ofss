/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef CONF_ARGS_H
#define CONF_ARGS_H 1

#define CONF_DP_ARGS_NAME    "datapath"
#define CONF_DP_ARGS_KEY     'd'
#define CONF_DP_ARGS_ARG     "ARGS"
#define CONF_DP_ARGS_FLAGS   0
#define CONF_DP_ARGS_DOC \
     "Various datapath-related settings. "             \
     "ARGS is a comma separated list of settings. "    \
     "Supported settings: dpid:0123456789abcdef. "     \
     "Example: dpid:0123456789abcdef.\n"


#define CONF_CTRLS_ARGS_NAME    "controllers"
#define CONF_CTRLS_ARGS_KEY     'c'
#define CONF_CTRLS_ARGS_ARG     "CTRLS"
#define CONF_CTRLS_ARGS_FLAGS   OPTION_ARG_OPTIONAL
#define CONF_CTRLS_ARGS_DOC \
     "The list of controllers the ofs should try to connect to. "         \
     "CTRLS is a comma separated list of controller addresses. "          \
     "Each address can be prefixed by the transport type to be used. "    \
     "If no transport is defined, tcp will be used. "                     \
     "If no transport port is defined, the default 6633 will be used. "   \
     "Supported transports: tcp. "                                        \
     "Example: 10.1.0.1,10.0.0.2:6655,ssl:10.1.0.3:6666.\n"

#define CONF_PORTS_ARGS_NAME    "ports"
#define CONF_PORTS_ARGS_KEY     'p'
#define CONF_PORTS_ARGS_ARG     "PORTS"
#define CONF_PORTS_ARGS_FLAGS 0
#define CONF_PORTS_ARGS_DOC \
    "The list of ports to be used by the ofs. "              \
    "PORTS is a comma separated list of port names. "        \
    "Use a colon to specify the port driver as a prefix. "   \
    "If no driver is defined, the pcap driver is used. "     \
    "Supported drivers: pcap. "                              \
    "Example: eth1,eth2,drv:p1,drv:p2.\n"


#define CONF_ARGS                                                      \
    {.name = CONF_DP_ARGS_NAME, .key =   CONF_DP_ARGS_KEY,             \
     .arg =  CONF_DP_ARGS_ARG,  .flags = CONF_DP_ARGS_FLAGS,           \
     .doc  = CONF_DP_ARGS_DOC},                                        \
    {.name = CONF_CTRLS_ARGS_NAME, .key =   CONF_CTRLS_ARGS_KEY,       \
     .arg =  CONF_CTRLS_ARGS_ARG,  .flags = CONF_CTRLS_ARGS_FLAGS,     \
     .doc  = CONF_CTRLS_ARGS_DOC},                                     \
    {.name = CONF_PORTS_ARGS_NAME, .key =   CONF_PORTS_ARGS_KEY,       \
     .arg =  CONF_PORTS_ARGS_ARG,  .flags = CONF_PORTS_ARGS_FLAGS,     \
     .doc  = CONF_PORTS_ARGS_DOC}


struct argp_state;

void *
conf_args_new();

void
conf_args_free(void *args);

void
conf_args_parse_dp(void *args_, char *arg, struct argp_state *state);

void
conf_args_parse_ctrls(void *args_, char *arg, struct argp_state *state);

void
conf_args_parse_ports(void *args_, char *arg, struct argp_state *state);

#endif /* CONF_ARGS_H */
