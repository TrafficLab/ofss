/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#include <stdio.h>
#include <stdbool.h>
#include <ev.h>
#include <pcap.h>

#include "info.h"

/*
 * Displays various system information when requested.
 */

static void
print_ev_backends(unsigned int b) {
    bool first = true;
    if ((b & EVBACKEND_SELECT) != 0) {  if (!first) { printf(", "); } printf("select"); first = false; }
    if ((b & EVBACKEND_POLL) != 0) {    if (!first) { printf(", "); } printf("poll"); first = false; }
    if ((b & EVBACKEND_EPOLL) != 0) {   if (!first) { printf(", "); } printf("epoll"); first = false; }
    if ((b & EVBACKEND_KQUEUE) != 0) {  if (!first) { printf(", "); } printf("kqueue"); first = false; }
    if ((b & EVBACKEND_DEVPOLL) != 0) { if (!first) { printf(", "); } printf("devpoll"); first = false; }
    if ((b & EVBACKEND_PORT) != 0) {    if (!first) { printf(", "); } printf("port"); first = false; }
}

static void
print_pcap_devs() {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("ERROR: %s", errbuf);
        return;
    }

    bool first = true;
    pcap_if_t *d;
    for (d = alldevs; d != NULL; d = d->next) {
        if (!first) { printf(", ");}
        first = false;
        printf("%s", d->name);
    }
    pcap_freealldevs(alldevs);
}

void
info() {
    printf("============================================================\n");
    printf("                            INFO\n");
    printf("------------------------------------------------------------\n");
    printf("Libev:\n");
    printf("\tVersion: %d.%d\n", ev_version_major(), ev_version_minor());
    printf("\tSupported backends: "); print_ev_backends(ev_supported_backends()); printf("\n");
    printf("\tRecommended backends: "); print_ev_backends(ev_recommended_backends()); printf("\n");
    printf("\tEmbeddable backends: "); print_ev_backends(ev_embeddable_backends()); printf("\n");
    printf("\tDefault backend: "); print_ev_backends(ev_backend(EV_DEFAULT)); printf("\n");
    printf("Libpcap:\n");
    printf("\tVersion: %s\n", pcap_lib_version());
    printf("\tDevices: "), print_pcap_devs(); printf("\n");
    printf("============================================================\n");
}
