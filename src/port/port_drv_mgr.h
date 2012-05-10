/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef PORT_DRV_MGR_H
#define PORT_DRV_MGR_H 1


struct port_drv;

void
port_drv_mgr_init();

struct port_drv *
port_drv_mgr_get(const char *name);


#endif /* PORT_DRV_MGR_H */
