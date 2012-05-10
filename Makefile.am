# do not check for standard stuff, like AM_PROG_CC_C_O
AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = ofss

ofss_SOURCES =                               \
    src/config/conf.c                        \
    src/config/conf_args.c                   \
    src/control/ctrl.c                       \
    src/control/ctrl_conn.c                  \
    src/control/ctrl_conn_tcp.c              \
    src/datapath/action.c                    \
    src/datapath/action_list.c               \
    src/datapath/action_set.c                \
    src/datapath/dp.c                        \
    src/datapath/dp_bufs.c                   \
    src/datapath/dp_ctrl.c                   \
    src/datapath/dp_mgr.c                    \
    src/datapath/flow_entry.c                \
    src/datapath/flow_table.c                \
    src/datapath/group_entry.c               \
    src/datapath/group_table.c               \
    src/datapath/match_standard.c            \
    src/datapath/pipeline.c                  \
    src/datapath/pipeline_packet.c           \
    src/datapath/protocol_stack.c            \
    src/lib/info.c                           \
    src/lib/message_box.c                    \
    src/lib/pkt_buf.c                        \
    src/lib/thread_id.c                      \
    src/logger/logger_args.c                 \
    src/logger/logger_mgr.c                  \
    src/logger/logger.c                      \
    src/oflib/ofl_actions_pack.c             \
    src/oflib/ofl_actions_print.c            \
    src/oflib/ofl_actions_unpack.c           \
    src/oflib/ofl_actions.c                  \
    src/oflib/ofl_messages_pack.c            \
    src/oflib/ofl_messages_print.c           \
    src/oflib/ofl_messages_unpack.c          \
    src/oflib/ofl_messages.c                 \
    src/oflib/ofl_print.c                    \
    src/oflib/ofl_structs_pack.c             \
    src/oflib/ofl_structs_print.c            \
    src/oflib/ofl_structs_unpack.c           \
    src/oflib/ofl_structs.c                  \
    src/port/port_drv.c                      \
    src/port/port_drv_mgr.c                  \
    src/port/pcap/pcap_drv.c                 \
    src/port/pcap/pcap_drv_linux.c           \
    src/port/pcap/pcap_port.c                \
    src/ofss.c

#NOTE: autoconf adds "-g -O2" by default
#O0: for debugging
AM_CPPFLAGS = -I./src -I./vendor   \
              $(PCAP_CFLAGS)       \
              $(LIBEV_CFLAGS)      \
              -Wall -W -O0

AM_LDFLAGS = -pthread

LDADD = $(PCAP_LIBS)   \
        $(LIBEV_LIBS)

# additional files to be deleted by "make maintainer-clean"
MAINTAINERCLEANFILES =     \
    Makefile.in            \
    configure              \
    aclocal.m4             \
    build-aux/depcomp      \
    build-aux/install-sh   \
    build-aux/missing
