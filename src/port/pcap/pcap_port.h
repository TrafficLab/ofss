/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef PCAP_PORT_H
#define PCAP_PORT_H 1

#include <stddef.h>

struct pcap_port;
struct pcap_drv;

struct pcap_port *
pcap_port_open(struct pcap_drv *pcap_drv, size_t id, const char *name);

#endif /* PCAP_PORT_H */
