dnl config.m4 for waf extension

PHP_ARG_ENABLE([waf],
  [whether to enable waf support],
  [AS_HELP_STRING([--enable-waf],
    [Enable waf support])])

PHP_ARG_WITH([modsecurity],
  [whether to enable ModSecurity integration],
  [AS_HELP_STRING([--with-modsecurity[=DIR]],
    [Enable ModSecurity integration, DIR is the prefix to ModSecurity installation])],
  [no],
  [no])

if test "$PHP_WAF" != "no"; then
  AC_DEFINE(HAVE_WAF, 1, [Whether you have waf])

  dnl Check for ModSecurity if enabled
  if test "$PHP_MODSECURITY" != "no"; then
    AC_DEFINE(HAVE_MODSECURITY, 1, [Whether you have ModSecurity])

    dnl Check for ModSecurity installation
    if test "$PHP_MODSECURITY" != "yes"; then
      MODSECURITY_SEARCH_PATH="$PHP_MODSECURITY"
    else
      MODSECURITY_SEARCH_PATH="/usr/local /usr"
    fi

    dnl Find modsecurity.h
    AC_MSG_CHECKING([for ModSecurity headers])
    for i in $MODSECURITY_SEARCH_PATH; do
      if test -r $i/include/modsecurity/modsecurity.h; then
        MODSECURITY_INCLUDE_DIR=$i/include
        AC_MSG_RESULT([found in $i/include])
        break
      fi
    done

    if test -z "$MODSECURITY_INCLUDE_DIR"; then
      AC_MSG_ERROR([Cannot find ModSecurity headers. Please install libmodsecurity-dev or specify --with-modsecurity=DIR])
    fi

    dnl Find libmodsecurity
    AC_MSG_CHECKING([for ModSecurity library])
    for i in $MODSECURITY_SEARCH_PATH; do
      if test -r $i/lib/libmodsecurity.so -o -r $i/lib/x86_64-linux-gnu/libmodsecurity.so; then
        MODSECURITY_LIB_DIR=$i/lib
        AC_MSG_RESULT([found in $i/lib])
        break
      fi
    done

    if test -z "$MODSECURITY_LIB_DIR"; then
      AC_MSG_ERROR([Cannot find ModSecurity library. Please install libmodsecurity or specify --with-modsecurity=DIR])
    fi

    dnl Add include path
    PHP_ADD_INCLUDE($MODSECURITY_INCLUDE_DIR)

    dnl msc_set_request_hostname was added in libmodsecurity 3.0.13. Older
    dnl builds (Debian bookworm 3.0.9) lack it, so modsec.c must not reference
    dnl it or waf.so fails to dlopen. Falls back to a no op.
    dnl PHP_ADD_INCLUDE feeds the makefile but not autoconf's preprocessor, so
    dnl put the include dir on CPPFLAGS for the declaration check, otherwise
    dnl the header is not found and the symbol is silently declared absent on
    dnl every build (including 3.0.13+).
    saved_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS -I$MODSECURITY_INCLUDE_DIR"
    AC_CHECK_DECL([msc_set_request_hostname],
        [AC_DEFINE([HAVE_MSC_SET_REQUEST_HOSTNAME], 1,
            [Whether msc_set_request_hostname is available])],
        [],
        [[#include "modsecurity/modsecurity.h"]
         [#include "modsecurity/transaction.h"]]
    )
    CPPFLAGS="$saved_CPPFLAGS"

    dnl Add library
    PHP_ADD_LIBRARY_WITH_PATH(modsecurity, $MODSECURITY_LIB_DIR, WAF_SHARED_LIBADD)

    dnl ModSecurity needs the C++ standard library
    PHP_ADD_LIBRARY(stdc++, 1, WAF_SHARED_LIBADD)

    PHP_SUBST(WAF_SHARED_LIBADD)
  fi

  PHP_NEW_EXTENSION(waf,
    php_waf.c modsec.c,
    $ext_shared)
fi
