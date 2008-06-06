#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
dnl AC_INIT(FULL-PACKAGE-NAME, VERSION, BUG-REPORT-ADDRESS)
AC_INIT(src/pcaptxt.c)
AM_INIT_AUTOMAKE(pcaptxt,  esyscmd([tr -d '\n' < VERSION]))
dnl AC_CONFIG_SRCDIR([pcaptxt.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lpcap':
AC_CHECK_LIB([pcap], [main])

dnl ################################################
dnl # PCAP stuff. (from Bro)
dnl ################################################
AC_LBL_LIBPCAP(V_PCAPDEP, V_INCLS)
CPPFLAGS="$CPPFLAGS $V_INCLS"
AC_CHECK_HEADERS(pcap-int.h)
AC_CHECK_FUNCS(bpf_set_bufsize)
dnl ################################################
dnl # Check whether pcap provides pcap_version
dnl ################################################
AC_MSG_CHECKING([for pcap_version in libpcap])
AC_LINK_IFELSE(
	AC_LANG_PROGRAM([extern char pcap_version[];], [puts(pcap_version);]),
	AC_MSG_RESULT(yes)
	AC_DEFINE(PCAP_VERSION_STRING,,[Have a version string in libpcap]),
	AC_MSG_RESULT(no))
dnl ################################################
dnl # Check whether linking to pcap works 
dnl ################################################
AC_CHECK_LIB(pcap, main, , AC_MSG_ERROR([pcaptxt requires pcap.]))



# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])
AC_CHECK_HEADERS(memory.h netinet/in.h socket.h getopt.h)
AC_CHECK_HEADERS(net/ethernet.h netinet/ether.h netinet/if_ether.h sys/ethernet.h,,,
		[#include <sys/types.h>
		#include <netinet/in.h>])
# see if we have sin_len 
AC_CHECK_MEMBER(struct sockaddr_in.sin_len,
	[AC_DEFINE(SIN_LEN,,[have sin_len field in sockaddr_in])],,
	[ 
#if HAVE_SYS_TYPES_H
#	include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
#	include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#	include <netinet/in.h>
#endif
])  



# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([gettimeofday inet_ntoa memchr memset strcasecmp strerror strncasecmp])

#AC_CONFIG_FILES([Makefile])
AC_OUTPUT([Makefile
		src/Makefile
		])


