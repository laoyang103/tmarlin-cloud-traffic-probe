#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(tmarlin, 1.0, aa@qq.com)
AM_INIT_AUTOMAKE(tmarlin,1.0)
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
# FIXME: Replace `main' with a function in `-ldl':
AC_CHECK_LIB([dl], [main])
# FIXME: Replace `main' with a function in `-lm':
AC_CHECK_LIB([m], [main])
# FIXME: Replace `main' with a function in `-lpthread':
AC_CHECK_LIB([pthread], [main])
# FIXME: Replace `main' with a function in `-lpthread':
AC_CHECK_LIB([pcap], [main])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h float.h limits.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h sys/vfs.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_CHECK_FUNCS([floor getcwd gethostbyname gethostname inet_ntoa localtime_r memset pow socket strchr strerror strstr])

AC_OUTPUT(Makefile)
