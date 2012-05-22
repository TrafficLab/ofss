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
 * Functions for filling port data structures in a Linux environment.
 */

#include <stdio.h>
#include <errno.h>
#include "logger/logger.h"
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <openflow/openflow.h>
#include "pcap_drv_int.h"

/* Fill the port statistics. */
void
pcap_port_fill(struct pcap_port *pcap_port) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, pcap_port->name, sizeof ifr.ifr_name);

    struct ethtool_cmd ecmd;
    ifr.ifr_data = (caddr_t) &ecmd;
    memset(&ecmd, 0, sizeof ecmd);
    ecmd.cmd = ETHTOOL_GSET;

    int ret = ioctl(pcap_port->fd, SIOCETHTOOL, &ifr);
    if (ret != 0) {
        char errbuf[BUFSIZ];
        strerror_r(errno, errbuf, BUFSIZ);
        logger_log(pcap_port->logger, LOG_WARN, "ethtool failed: %s.", errbuf);
        return;
    }

    if ((ecmd.supported & SUPPORTED_10baseT_Half) != 0) { pcap_port->of_port->supported |= OFPPF_10MB_HD; }
    if ((ecmd.supported & SUPPORTED_10baseT_Full) != 0) { pcap_port->of_port->supported |= OFPPF_10MB_FD; }
    if ((ecmd.supported & SUPPORTED_100baseT_Half) != 0) { pcap_port->of_port->supported |= OFPPF_100MB_HD; }
    if ((ecmd.supported & SUPPORTED_100baseT_Full) != 0) { pcap_port->of_port->supported |= OFPPF_100MB_FD; }
    if ((ecmd.supported & SUPPORTED_1000baseT_Half) != 0) { pcap_port->of_port->supported |= OFPPF_1GB_HD; }
    if ((ecmd.supported & SUPPORTED_1000baseT_Full) != 0) { pcap_port->of_port->supported |= OFPPF_1GB_FD; }

    if ((ecmd.supported & SUPPORTED_Autoneg) != 0) { pcap_port->of_port->supported |= OFPPF_AUTONEG; }
    if ((ecmd.supported & SUPPORTED_TP) != 0) { pcap_port->of_port->supported |= OFPPF_COPPER; }
    if ((ecmd.supported & SUPPORTED_FIBRE) != 0) { pcap_port->of_port->supported |= OFPPF_FIBER; }
    if ((ecmd.supported & SUPPORTED_BNC) != 0) { pcap_port->of_port->supported |= OFPPF_COPPER; }
    if ((ecmd.supported & SUPPORTED_Pause) != 0) { pcap_port->of_port->supported |= OFPPF_PAUSE; }
    if ((ecmd.supported & SUPPORTED_Asym_Pause) != 0) { pcap_port->of_port->supported |= OFPPF_PAUSE_ASYM; }

#ifdef SUPPORTED_10000baseT_Full
    if ((ecmd.supported & SUPPORTED_10000baseT_Full) != 0) { pcap_port->of_port->supported |= OFPPF_10GB_FD; }
#endif
#ifdef SUPPORTED_2500baseX_Full
    if ((ecmd.supported & SUPPORTED_2500baseX_Full) != 0) { pcap_port->of_port->supported |= OFPPF_OTHER; }
#endif
#ifdef SUPPORTED_1000baseKX_Full
    if ((ecmd.supported & SUPPORTED_1000baseKX_Full) != 0) { pcap_port->of_port->supported |= OFPPF_OTHER; }
#endif
#ifdef SUPPORTED_10000baseKX4_Full
    if ((ecmd.supported & SUPPORTED_10000baseKX4_Full) != 0) { pcap_port->of_port->supported |= OFPPF_10GB_FD; }
#endif
#ifdef SUPPORTED_10000baseKR_Full
    if ((ecmd.supported & SUPPORTED_10000baseKR_Full) != 0) { pcap_port->of_port->supported |= OFPPF_10GB_FD; }
#endif
#ifdef SUPPORTED_10000baseR_FEC
    if ((ecmd.supported & SUPPORTED_10000baseR_FEC) != 0) { pcap_port->of_port->supported |= OFPPF_10GB_FD; }
#endif
#ifdef SUPPORTED_20000baseMLD2_Full
    if ((ecmd.supported & SUPPORTED_20000baseMLD2_Full) != 0) { pcap_port->of_port->supported |= OFPPF_10GB_FD; }
#endif
#ifdef SUPPORTED_20000baseKR2_Full
    if ((ecmd.supported & SUPPORTED_20000baseKR2_Full) != 0) { pcap_port->of_port->supported |= OFPPF_10GB_FD; }
#endif

    if ((ecmd.advertising & SUPPORTED_10baseT_Half) != 0) { pcap_port->of_port->advertised |= OFPPF_10MB_HD; }
    if ((ecmd.advertising & SUPPORTED_10baseT_Full) != 0) { pcap_port->of_port->advertised |= OFPPF_10MB_FD; }
    if ((ecmd.advertising & SUPPORTED_100baseT_Half) != 0) { pcap_port->of_port->advertised |= OFPPF_100MB_HD; }
    if ((ecmd.advertising & SUPPORTED_100baseT_Full) != 0) { pcap_port->of_port->advertised |= OFPPF_100MB_FD; }
    if ((ecmd.advertising & SUPPORTED_1000baseT_Half) != 0) { pcap_port->of_port->advertised |= OFPPF_1GB_HD; }
    if ((ecmd.advertising & SUPPORTED_1000baseT_Full) != 0) { pcap_port->of_port->advertised |= OFPPF_1GB_FD; }

    if ((ecmd.advertising & SUPPORTED_Autoneg) != 0) { pcap_port->of_port->advertised |= OFPPF_AUTONEG; }
    if ((ecmd.advertising & SUPPORTED_TP) != 0) { pcap_port->of_port->advertised |= OFPPF_COPPER; }
    if ((ecmd.advertising & SUPPORTED_FIBRE) != 0) { pcap_port->of_port->advertised |= OFPPF_FIBER; }
    if ((ecmd.advertising & SUPPORTED_BNC) != 0) { pcap_port->of_port->advertised |= OFPPF_COPPER; }
    if ((ecmd.advertising & SUPPORTED_Pause) != 0) { pcap_port->of_port->advertised |= OFPPF_PAUSE; }
    if ((ecmd.advertising & SUPPORTED_Asym_Pause) != 0) { pcap_port->of_port->advertised |= OFPPF_PAUSE_ASYM; }

#ifdef SUPPORTED_10000baseT_Full
    if ((ecmd.advertising & SUPPORTED_10000baseT_Full) != 0) { pcap_port->of_port->advertised |= OFPPF_10GB_FD; }
#endif
#ifdef SUPPORTED_2500baseX_Full
    if ((ecmd.advertising & SUPPORTED_2500baseX_Full) != 0) { pcap_port->of_port->advertised |= OFPPF_OTHER; }
#endif
#ifdef SUPPORTED_1000baseKX_Full
    if ((ecmd.advertising & SUPPORTED_1000baseKX_Full) != 0) { pcap_port->of_port->advertised |= OFPPF_OTHER; }
#endif
#ifdef SUPPORTED_10000baseKX4_Full
    if ((ecmd.advertising & SUPPORTED_10000baseKX4_Full) != 0) { pcap_port->of_port->advertised |= OFPPF_10GB_FD; }
#endif
#ifdef SUPPORTED_10000baseKR_Full
    if ((ecmd.advertising & SUPPORTED_10000baseKR_Full) != 0) { pcap_port->of_port->advertised |= OFPPF_10GB_FD; }
#endif
#ifdef SUPPORTED_10000baseR_FEC
    if ((ecmd.advertising & SUPPORTED_10000baseR_FEC) != 0) { pcap_port->of_port->advertised |= OFPPF_10GB_FD; }
#endif
#ifdef SUPPORTED_20000baseMLD2_Full
    if ((ecmd.advertising & SUPPORTED_20000baseMLD2_Full) != 0) { pcap_port->of_port->advertised |= OFPPF_10GB_FD; }
#endif
#ifdef SUPPORTED_20000baseKR2_Full
    if ((ecmd.advertising & SUPPORTED_20000baseKR2_Full) != 0) { pcap_port->of_port->advertised |= OFPPF_10GB_FD; }
#endif

    if (ecmd.speed == SPEED_10 && ecmd.duplex) { pcap_port->of_port->curr = OFPPF_10MB_FD; }
    if (ecmd.speed == SPEED_10 && !ecmd.duplex) { pcap_port->of_port->curr = OFPPF_10MB_HD; }
    if (ecmd.speed == SPEED_100 && ecmd.duplex) { pcap_port->of_port->curr = OFPPF_100MB_FD; }
    if (ecmd.speed == SPEED_100 && !ecmd.duplex) { pcap_port->of_port->curr = OFPPF_100MB_HD; }
    if (ecmd.speed == SPEED_1000 && ecmd.duplex) { pcap_port->of_port->curr = OFPPF_1GB_FD; }
    if (ecmd.speed == SPEED_1000 && !ecmd.duplex) { pcap_port->of_port->curr = OFPPF_1GB_HD; }
    if (ecmd.speed == SPEED_1000 && ecmd.duplex) { pcap_port->of_port->curr = OFPPF_1GB_FD; }
    if (ecmd.speed == SPEED_10000) { pcap_port->of_port->curr = OFPPF_10GB_FD; }

    if ((ecmd.port & SUPPORTED_Autoneg) != 0) { pcap_port->of_port->curr |= OFPPF_AUTONEG; }
    if ((ecmd.port & SUPPORTED_TP) != 0) { pcap_port->of_port->curr |= OFPPF_COPPER; }
    if ((ecmd.port & SUPPORTED_FIBRE) != 0) { pcap_port->of_port->curr |= OFPPF_FIBER; }
    if ((ecmd.port & SUPPORTED_BNC) != 0) { pcap_port->of_port->curr |= OFPPF_COPPER; }
    if ((ecmd.port & SUPPORTED_Pause) != 0) { pcap_port->of_port->curr |= OFPPF_PAUSE; }
    if ((ecmd.port & SUPPORTED_Asym_Pause) != 0) { pcap_port->of_port->curr |= OFPPF_PAUSE_ASYM; }

    //TODO: speed OK?
    pcap_port->of_port->curr_speed = ecmd.speed;
    pcap_port->of_port->max_speed = ecmd.speed;

    /* Hw addr */
    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, pcap_port->name, sizeof ifr.ifr_name);

    ret = ioctl(pcap_port->fd, SIOCGIFHWADDR, &ifr);
    if (ret != 0) {
        char errbuf[BUFSIZ];
        strerror_r(errno, errbuf, BUFSIZ);
        logger_log(pcap_port->logger, LOG_WARN, "hw_addr failed: %s.", errbuf);
        return;
    }

    //TODO: check ifr.ifr_hwaddr.sa_family ?
    memcpy(pcap_port->of_port->hw_addr, ifr.ifr_hwaddr.sa_data, OFP_ETH_ALEN);
}
