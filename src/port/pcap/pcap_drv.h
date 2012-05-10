/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef PCAP_DRV_H
#define PCAP_DRV_H 1

#include <stdbool.h>
#include "lib/openflow.h"

#define PCAP_DRIVER_NAME "pcap"


struct pcap_drv;
struct port_drv;
struct pkt_buf;


struct pcap_drv *
pcap_drv_init(struct port_drv *drv);

ssize_t
pcap_drv_get_port(struct pcap_drv *pcap_drv, const char *name);

bool
pcap_drv_assign_dp_port(struct pcap_drv *drv, size_t drv_port_no, size_t dp_uid, of_port_no_t dp_port_no);

bool
pcap_drv_send_pkt(struct pcap_drv *drv, size_t drv_port_no, struct pkt_buf *pkt_buf);

struct ofl_port *
pcap_drv_get_port_desc(struct pcap_drv *drv, size_t drv_port_no);

struct ofl_port_stats *
pcap_drv_get_port_stats(struct pcap_drv *drv, size_t drv_port_no);

const uint8_t *
pcap_drv_get_port_addr(struct pcap_drv *drv, size_t drv_port_no);

void
pcap_drv_port_mod(struct pcap_drv *drv, size_t drv_port_no, uint32_t config);

#endif /* PCAP_DRV_H */
