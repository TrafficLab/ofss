/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef PORT_DRV_H
#define PORT_DRV_H 1

#include "port_drv_int.h"

struct port_drv;
struct pkt_buf;
struct ofl_port;
struct ofl_port_stats;


struct port_drv *
port_drv_init(enum port_drv_type type);

ssize_t
port_drv_get_port(struct port_drv *drv, const char *name);

bool
port_drv_assign_dp_port(struct port_drv *drv, size_t drv_port_no, size_t dp_uid, of_port_no_t dp_port_no);

bool
port_drv_send_pkt(struct port_drv *drv, size_t drv_port_no, struct pkt_buf *pkt_buf);

const char *
port_drv_get_name(struct port_drv *drv);

struct ofl_port *
port_drv_get_port_desc(struct port_drv *drv, size_t drv_port_no);

struct ofl_port_stats *
port_drv_get_port_stats(struct port_drv *drv, size_t drv_port_no);

const uint8_t *
port_drv_get_port_addr(struct port_drv *drv, size_t drv_port_no);

void
port_drv_port_mod(struct port_drv *drv, size_t drv_port_no, uint32_t config);

#endif /* PORT_DRV_H */
