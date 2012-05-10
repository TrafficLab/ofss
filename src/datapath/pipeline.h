/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef PIPELINE_H
#define PIPELINE_H 1

#include <stdint.h>
#include "lib/openflow.h"

struct dp;
struct pl_pkt;


void
pipeline_process(struct dp_loop *dp_loop, struct pl_pkt *pl_pkt);


#endif /* PIPELINE_H */
