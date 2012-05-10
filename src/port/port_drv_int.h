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
 * Common internal structure for the port drivers.
 */

#ifndef PORT_DRV_INT_H
#define PORT_DRV_INT_H 1

#include "pcap/pcap_drv.h"

#define DEFAULT_DRIVER_NAME  PCAP_DRIVER_NAME


#define PORT_DRVS_NUM   1
enum port_drv_type {
    PORT_DRV_PCAP
};

struct port_drv {
    enum port_drv_type   type;
    const char          *name;
    struct logger       *logger;
    void                *private;
};


#endif /* _PORT_DRV_INT_H_ */
