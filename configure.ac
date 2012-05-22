# require autoconf version >= 2.65
AC_PREREQ([2.65])
# initialize project
AC_INIT([OFSS], [0.1], [zoltan.lajos.kis@ericsson.com],
        [ofss], [https://github.com/TrafficLab/ofss/])

# check for source dir
AC_CONFIG_SRCDIR([src/ofss.c])


# auxiliary build files go here
AC_CONFIG_AUX_DIR([build-aux])

#find and probe C compiler
AC_PROG_CC

# use the C compiler for the following checks
AC_LANG([C])

# Checks for header files.
AC_CHECK_HEADERS([inttypes.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRERROR_R
AC_CHECK_FUNCS([localtime_r memmove memset socket strchr strdup strspn])

#init automake
#foreign: do not search/create NEWS, README, ChangeLog, ...
#subdir-objects: put .o files to subdirs, not to project root
AM_INIT_AUTOMAKE([1.11 foreign subdir-objects -Wall -Werror])
AC_CONFIG_FILES([Makefile])

# DEPENDENCIES

# pcap dependency
AC_ARG_WITH([pcap-include-path],
  [AS_HELP_STRING([--with-pcap-include-path],
    [location of the pcap headers, defaults to /usr/include])],
  [PCAP_CFLAGS="-I$withval"],
  [PCAP_CFLAGS='-I/usr/include'])
AC_SUBST([PCAP_CFLAGS])

AC_ARG_WITH([pcap-lib-path],
  [AS_HELP_STRING([--with-pcap-lib-path],
    [location of the pcap libraries])],
  [PCAP_LIBS="-L$withval -lpcap"],
  [PCAP_LIBS='-lpcap'])
AC_SUBST([PCAP_LIBS])

# libev dependency
AC_ARG_WITH([libev-include-path],
  [AS_HELP_STRING([--with-libev-include-path],
    [location of the libev headers, defaults to /usr/include])],
  [LIBEV_CFLAGS="-I$withval"],
  [LIBEV_CFLAGS='-I/usr/include'])
AC_SUBST([LIBEV_CFLAGS])

AC_ARG_WITH([libev-lib-path],
  [AS_HELP_STRING([--with-libev-lib-path],
    [location of the libev libraries])],
  [LIBEV_LIBS="-L$withval -lev"],
  [LIBEV_LIBS='-lev'])
AC_SUBST([LIBEV_LIBS])


# finally generate Makefile, etc.
AC_OUTPUT
