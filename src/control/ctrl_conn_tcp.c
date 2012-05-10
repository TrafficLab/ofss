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
 * TCP connection handler for controller communication.
 */
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <ev.h>
#include <openflow/openflow.h>
#include <datapath/dp.h>
#include "logger/logger.h"
#include "logger/logger_mgr.h"
#include "lib/compiler.h"
#include "lib/logger_names.h"
#include "ctrl_conn.h"
#include "ctrl_conn_buffer.h"
#include "ctrl_conn_tcp.h"
#include "ctrl_int.h"

#define DEFAULT_PORT  "6633"

#define RETRY_WAIT          1.
#define CONNECTING_TIMEOUT  3.
#define CONNECTED_IDLE     20.
#define CONNECTED_TIMEOUT  25.

struct addrinfo;

enum conn_tcp_state {
    CONN_TCP_DISCONNECTED,
    CONN_TCP_CONNECTING,
    CONN_TCP_CONNECTED,
    CONN_TCP_WAITRETRY
};


struct conn_tcp {
    struct conn          *conn;
    struct logger        *logger;
    enum conn_tcp_state   state;
    struct addrinfo      *addrinfos;
    int                   sockfd;
    struct addrinfo      *last_addr;
    ev_timer              timer;
    ev_tstamp             last_read;
    ev_io                 read_watcher;
    ev_io                 write_watcher;
    struct buffer        *read_buffer;
    char                  errbuf[BUFSIZ];
};



static void
tcp_disconnected(struct conn_tcp *tcp);
static void
tcp_waitretry(struct conn_tcp *tcp);
static void
tcp_connected(struct conn_tcp *tcp);



/* Called when data is available on the controller's socket.
 * Reads the data to the buffer, and processes if enough data is received. */
static void
tcp_read(struct conn_tcp *tcp) {
    bool cont = true;

    do {
        size_t read_len = ctrl_conn_read(tcp->conn, buffer_data(tcp->read_buffer), buffer_data_len(tcp->read_buffer));
        if (read_len > 0) {
            buffer_data_read(tcp->read_buffer, read_len);
            continue;
        }

        size_t msg_len = ctrl_conn_msg_len(buffer_data(tcp->read_buffer), buffer_data_len(tcp->read_buffer));
        if (msg_len > 0) {
            buffer_ensurelen(tcp->read_buffer, msg_len);
            read_len = msg_len - buffer_data_len(tcp->read_buffer);

            ssize_t ret = read(tcp->sockfd, buffer_tail(tcp->read_buffer), read_len);
            if (ret < 0) {
                if (errno == EWOULDBLOCK || errno == EAGAIN) {
                    // nothing more to read now
                    cont = false;
                } else {
                    // TODO: handle error
                    if (logger_is_enabled(tcp->logger, LOG_WARN)) {
                        strerror_r(errno, tcp->errbuf, BUFSIZ);
                        logger_log(tcp->logger, LOG_WARN, "read error: %s", tcp->errbuf);
                    }

                    cont = false;
                }
            } else if (ret == 0) {
                // 0 is assumed to be a sign of disconnect
                logger_log(tcp->logger, LOG_WARN, "Disconnect (a).");

                tcp_disconnected(tcp);
                return;
            } else {
                logger_log(tcp->logger, LOG_DEBUG, "read %d bytes (a).", ret);
                buffer_data_write(tcp->read_buffer, ret);
                if ((size_t)ret < read_len) { // ret > 0
                    // need more read
                    cont = false;
                } else {
                    read_len = ctrl_conn_read(tcp->conn, buffer_data(tcp->read_buffer), buffer_data_len(tcp->read_buffer));
                    if (read_len > 0) {
                        buffer_data_read(tcp->read_buffer, read_len);
                        break;
                    }
                }
            }
        } else {
            ssize_t ret = read(tcp->sockfd, buffer_tail(tcp->read_buffer), buffer_tail_len(tcp->read_buffer));

            if (ret < 0) {
                if (errno == EWOULDBLOCK || errno == EAGAIN) {
                    // nothing more to read now
                    cont = false;
                } else {
                    // TODO: handle error
                    if (logger_is_enabled(tcp->logger, LOG_WARN)) {
                        strerror_r(errno, tcp->errbuf, BUFSIZ);
                        logger_log(tcp->logger, LOG_WARN, "read error: %s", tcp->errbuf);
                    }
                    cont = false;
                }
            } else if (ret == 0) {
                // 0 is assumed to be a sign of disconnect
                logger_log(tcp->logger, LOG_INFO, "Disconnect (b).");

                tcp_disconnected(tcp);
                return;
            } else {
                logger_log(tcp->logger, LOG_DEBUG, "read %d bytes (b).", ret);
                buffer_data_write(tcp->read_buffer, ret);
            }
        }
    } while (cont);
}


/* Callback called when a connection's socket becomes readable. */
static void
tcp_read_cb(struct ev_loop *loop, ev_io *w, int revents UNUSED_ATTR) {
    struct conn_tcp *tcp = (struct conn_tcp *)(w->data);

    switch (tcp->state) {
        case CONN_TCP_CONNECTED: {
            tcp->last_read = ev_now(loop);
            tcp_read(tcp);
            break;
        }
        default: {
            logger_log(tcp->logger, LOG_WARN, "tcp_read_cb called from unexpected state (%d)",
                                            tcp->state);
            break;
        }
    }

}



/* Callback called when a connection's socket becomes writeable. */
static void
tcp_write_cb(struct ev_loop *loop, ev_io *w, int revents UNUSED_ATTR) {
    struct conn_tcp *tcp = (struct conn_tcp *)(w->data);

    struct ev_timer *timer = &(tcp->timer);
    struct ev_io    *write_watcher = &(tcp->write_watcher);

    switch (tcp->state) {
        case CONN_TCP_CONNECTING: {
            ev_timer_stop(loop, timer);
            ev_io_stop(loop, write_watcher);

            // NOTE: this can be either success or failure
            // NOTE: getpeername seems to work better than getsockopt(..SO_ERROR..)
            struct sockaddr_in name;
            socklen_t len = sizeof(struct sockaddr_in);
            if (getpeername(tcp->sockfd, (struct sockaddr *)&name, &len) >= 0) {
                tcp_connected(tcp);
            } else {
                tcp_waitretry(tcp);
            }
            break;
        }
        default: {
            logger_log(tcp->logger, LOG_WARN, "tcp_write_cb called from unexpected state (%d)",
                    tcp->state);
            ev_io_stop(loop, write_watcher);
            break;
        }
    }
}



/* Called when the connection's timer fires.
 * NOTE: For efficiency reasons the timer is always set to the next possible
 * event's time. At that time it is checked whether something really happened.
 * If not, the timer is reset for the next possible event. */
static void
tcp_timer_cb(struct ev_loop *loop, ev_timer *w, int revents UNUSED_ATTR) {
    struct conn_tcp *tcp = (struct conn_tcp *)(w->data);

    struct ev_io      *read_watcher = &(tcp->read_watcher);
    struct ev_io      *write_watcher = &(tcp->write_watcher);

    switch (tcp->state) {
        case CONN_TCP_CONNECTED: {
            ev_tstamp timeout = tcp->last_read - ev_now(loop) + CONNECTED_TIMEOUT;
            if (timeout < 0) {
                logger_log(tcp->logger, LOG_INFO, "Connection timed out.");

                ev_io_stop(loop, read_watcher);
                ev_io_stop(loop, write_watcher);

                tcp_disconnected(tcp);
                return;
            }

            ev_tstamp idle = tcp->last_read - ev_now(loop) + CONNECTED_IDLE;
            if (idle < 0) {
                // idle timeout
                logger_log(tcp->logger, LOG_DEBUG, "idle timeout.");

                ctrl_conn_idle(tcp->conn);

                ev_timer_set(w, timeout, 0.0/*no repeat*/);
                ev_timer_start(loop, w);
                return;
            }

            // assuming idle < timeout
            ev_timer_set(w, idle, 0.0/*no repeat*/);
            ev_timer_start(loop, w);

            break;
        }
        case CONN_TCP_CONNECTING: {
            // could not connect, retry later
            ev_io_stop(loop, write_watcher);
            tcp_waitretry(tcp);
            break;
        }
        case CONN_TCP_WAITRETRY: {
            tcp_disconnected(tcp);
            break;
        }
        default: {
            logger_log(tcp->logger, LOG_WARN, "tcp_timer_cb called from unexpected state (%d)",
                                             tcp->state);
            break;
        }
    }
}



/* Called when the connection enters the CONNECTED state. */
static void
tcp_connected(struct conn_tcp *tcp) {
    tcp->state = CONN_TCP_CONNECTED;

    logger_log(tcp->logger, LOG_INFO, "Connected.");

    //set TCP_NODELAY
    int one = 1;
    if (setsockopt(tcp->sockfd, SOL_TCP, TCP_NODELAY, &one, sizeof(one)) != 0) {
        logger_log(tcp->logger, LOG_WARN, "Error setting TCP_NODELAY.");
    }

    struct ev_timer *timer = &(tcp->timer);
    tcp->last_read = ev_now(tcp->conn->ctrl_loop->loop);
    ev_timer_set(timer, CONNECTED_IDLE, 0.0/*no repeat*/);
    ev_timer_start(tcp->conn->ctrl_loop->loop, timer);

    struct ev_io *read_watcher = &(tcp->read_watcher);
    ev_io_set(read_watcher, tcp->sockfd, EV_READ);
    ev_io_start(tcp->conn->ctrl_loop->loop, read_watcher);
}

/* Called when the connection could not connect, so it will
 * wait before the next attempt. */
static void
tcp_waitretry(struct conn_tcp *tcp) {
    tcp->state = CONN_TCP_WAITRETRY;

    logger_log(tcp->logger, LOG_INFO, "Connecting to failed; retrying later.");

    struct ev_timer *timer = &(tcp->timer);
    ev_timer_set(timer, RETRY_WAIT, 0.0/*no repeat*/);
    ev_timer_start(tcp->conn->ctrl_loop->loop, timer);
}


/* Called when the connection is progressing. */
static void
tcp_connecting(struct conn_tcp *tcp) {
    tcp->state = CONN_TCP_CONNECTING;

    logger_log(tcp->logger, LOG_DEBUG, "Connecting.");

    struct ev_timer *timer = &(tcp->timer);
    ev_timer_set(timer, CONNECTING_TIMEOUT, 0/*no repeat*/);
    ev_timer_start(tcp->conn->ctrl_loop->loop, timer);

    struct ev_io *write_watcher = &(tcp->write_watcher);
    ev_io_set(write_watcher, tcp->sockfd, EV_WRITE);
    ev_io_start(tcp->conn->ctrl_loop->loop, write_watcher);

}


/* Tries to connect to the controller on the given address. */
static bool
tcp_disconnected_try(struct conn_tcp *tcp, struct addrinfo *p) {
    // try opening socket
    if ((tcp->sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
        logger_log(tcp->logger, LOG_DEBUG, "Error opening socket; trying next addr.");
        return false;
    }

    // set to nonblocking
    int flags = fcntl(tcp->sockfd, F_GETFL);
    flags |= O_NONBLOCK;
    if (fcntl(tcp->sockfd, F_SETFL, flags) == -1) {
        logger_log(tcp->logger, LOG_DEBUG, "Error setting socket to non-blocking; trying next addr.");
        close(tcp->sockfd);
        return false;
    }

    if (connect(tcp->sockfd, p->ai_addr, p->ai_addrlen) == -1) {
        if (errno == EINPROGRESS || errno == EWOULDBLOCK) { // nonblocking connect in progress
            return true;
        } else {
            if (logger_is_enabled(tcp->logger, LOG_DEBUG)) {
                strerror_r(errno, tcp->errbuf, BUFSIZ);
                logger_log(tcp->logger, LOG_DEBUG, "Error connecting: %s; trying next addr.",
                        tcp->errbuf);
            }
            close(tcp->sockfd);
            return false;
        }
    }

    if (logger_is_enabled(tcp->logger, LOG_DEBUG)) {
        strerror_r(errno, tcp->errbuf, BUFSIZ);
        logger_log(tcp->logger, LOG_DEBUG, "Error connecting: %s; trying next addr.",
                tcp->errbuf);
    }
    close(tcp->sockfd);
    return false;
}



/* Called when the connection enters the DISCONNECTED state.
 * It will attempt to connect to the controller. */
static void
tcp_disconnected(struct conn_tcp *tcp) {

    if (tcp->state != CONN_TCP_DISCONNECTED) {
        close(tcp->sockfd);
        tcp->state = CONN_TCP_DISCONNECTED;
    }

    struct ev_io *read_watcher = &(tcp->read_watcher);
    ev_io_stop(tcp->conn->ctrl_loop->loop, read_watcher);

    struct ev_io *write_watcher = &(tcp->write_watcher);
    ev_io_stop(tcp->conn->ctrl_loop->loop, write_watcher);

    struct ev_timer *timer = &(tcp->timer);
    ev_timer_stop(tcp->conn->ctrl_loop->loop, timer);

    logger_log(tcp->logger, LOG_DEBUG, "Trying to connect.");

    struct addrinfo *p;
    if (tcp->last_addr == NULL) {
        p = tcp->addrinfos;
    } else {
        p = tcp->last_addr->ai_next == NULL ? tcp->addrinfos : tcp->last_addr->ai_next;
    }
    for (; p != NULL; p = p->ai_next) {
        if (tcp_disconnected_try(tcp, p)) {
            tcp->last_addr = p;
            tcp_connecting(tcp);
            return;
        }
    }

    if (tcp->last_addr != NULL) {
        for (p = tcp->addrinfos; p != tcp->last_addr; p = p->ai_next) {
            if (tcp_disconnected_try(tcp, p)) {
                tcp->last_addr = p;
                tcp_connecting(tcp);
                return;
            }
        }
    }

    tcp_waitretry(tcp);
}

/* Adds a new TCP connection. */
struct conn_tcp * MALLOC_ATTR
ctrl_conn_tcp_new(struct conn *conn, const char *host, const char *port_) {
    struct addrinfo hints, *addrinfos;
    memset(&hints, 0, sizeof(struct addrinfo)); // set all fields to 0
    hints.ai_family   = AF_UNSPEC;   // both AF_INET and AF_INTET6
    hints.ai_socktype = SOCK_STREAM; // TCP
    //TODO: ai_protocol ?

    const char *port = port_ == NULL ? DEFAULT_PORT : port_;

    int ret;
    if ((ret = getaddrinfo(host, port, &hints, &addrinfos)) != 0) {
         logger_log(conn->ctrl_loop->logger, LOG_WARN, "Error with getaddrinfo for TCP:%s:%s: %s.",
                 host, port, gai_strerror(ret));
         //TODO free structures on failure
         return NULL;
     }

    struct conn_tcp *tcp = malloc(sizeof(struct conn_tcp));
    tcp->logger    = logger_mgr_get(LOGGER_NAME_CTRL_CONN_TCP, dp_get_uid(conn->ctrl_loop->dp), conn->id);
    tcp->state     = CONN_TCP_DISCONNECTED;
    tcp->sockfd    = -1;
    tcp->addrinfos = addrinfos;
    tcp->last_addr = NULL;
    tcp->conn      = conn;

    struct ev_io *read_watcher = &(tcp->read_watcher);
    read_watcher->data  = tcp;
    ev_init(read_watcher, tcp_read_cb);

    struct ev_io *write_watcher = &(tcp->write_watcher);
    write_watcher->data = tcp;
    ev_init(write_watcher, tcp_write_cb);

    struct ev_timer *timer = &(tcp->timer);
    timer->data = tcp;
    ev_init(timer, tcp_timer_cb);

    tcp->read_buffer = buffer_new(BUFSIZ);

    tcp_disconnected(tcp);

    return tcp;
}

/* Send data on the TCP connection. */
void
ctrl_conn_tcp_send(struct conn_tcp *tcp, uint8_t *buf, size_t buf_size) {
    if (tcp->state != CONN_TCP_CONNECTED) {
        logger_log(tcp->logger, LOG_INFO, "Trying to write, but not connected.");
        return;
    }
    //TODO check if state is connected
    int ret = write(tcp->sockfd, buf, buf_size);
    if (ret <= 0) {
        //TODO handle error
        //NOTE: if EAGAIN/EWOULDBLOCK, this should add stuff to the write buffer
        //      and check for writeability
        if (logger_is_enabled(tcp->logger, LOG_DEBUG)) {
            strerror_r(errno, tcp->errbuf, BUFSIZ);
            logger_log(tcp->logger, LOG_DEBUG, "Write error: %s.", tcp->errbuf);
        }
    } else {
        logger_log(tcp->logger, LOG_DEBUG, "Written %d bytes.", ret);
    }
}
