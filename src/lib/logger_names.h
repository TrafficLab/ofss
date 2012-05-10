/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef LOGGER_NAMES_H
#define LOGGER_NAMES_H 1

/*
 * A common place for defining logger names.
 */

#define LOGGER_NAME_CONFIG              "config"

#define LOGGER_NAME_CTRL_IF             "ctrl(%u)-if"
#define LOGGER_NAME_CTRL                "ctrl(%u)"
#define LOGGER_NAME_CTRL_CONN           "ctrl(%u)c(%u)"
#define LOGGER_NAME_CTRL_CONN_TCP       "ctrl(%u)tcp(%u)"

#define LOGGER_NAME_DP_MANAGER          "dp-mgr"
#define LOGGER_NAME_DP_IF               "dp(%u)-if"
#define LOGGER_NAME_DP                  "dp(%u)"
#define LOGGER_NAME_DP_CTRL             "dp(%u)ctrl"
#define LOGGER_NAME_DP_PL               "dp(%u)pl"
#define LOGGER_NAME_DP_PKT              "dp(%u)pkt"
#define LOGGER_NAME_DP_BUFS             "dp(%u)bufs"
#define LOGGER_NAME_DP_FLOWTABLE        "dp(%u)ft(%u)"
#define LOGGER_NAME_DP_GROUPTABLE       "dp(%u)gt"

#define LOGGER_NAME_PORT_DRV_MGR        "drv-mgr"
#define LOGGER_NAME_PORT_DRV            "drv(%s)"
#define LOGGER_NAME_PORT_DRV_PCAP_IF    "drv-pcap-if"
#define LOGGER_NAME_PORT_DRV_PCAP       "drv-pcap"
#define LOGGER_NAME_PORT_DRV_PCAP_PORT  "drv-pcap(%u)"

#define LOGGER_NAME_LOGGER_MGR          "logger-mgr"

#define LOGGER_NAME_THREAD_ID           "threads"

#endif /* LOGGER_NAMES_H */
