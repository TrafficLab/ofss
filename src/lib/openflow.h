/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef OPENFLOW_H
#define OPENFLOW_H 1

#include <stdint.h>

/*
 * Definitions for OpenFlow related special values not available in openflow.h,
 * and for OpenFlow related types.
 */

#define OF_NO_DPID    0ULL           /* special DPID value representing 'undefined'. */

#define OF_NO_BUFFER  0xffffffff     /* special buffer-id representing no buffer. */

#define OF_NO_PORT    0              /* special port number representing 'no port'. */

#define OF_ALL_TABLE 255             /* special table-id representing 'all tables'. */

typedef uint32_t of_xid_t;
typedef uint32_t of_bufferid_t;
typedef uint32_t of_port_no_t;
typedef uint32_t of_groupid_t;
typedef uint32_t of_queue_no_t;
typedef uint64_t of_dpid_t;
typedef uint64_t of_metadata_t;
typedef uint8_t  of_tableid_t;


#endif /* OPENFLOW_H */
