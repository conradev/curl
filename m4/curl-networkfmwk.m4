#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
#***************************************************************************

AC_DEFUN([CURL_WITH_NETWORKFRAMEWORK], [
AC_MSG_CHECKING([whether to enable Network.framework])
if test "x$OPT_NETWORKFRAMEWORK" != xno; then
  if test "x$OPT_NETWORKFRAMEWORK" != "xno" &&
     (test "x$cross_compiling" != "xno" || test -d "/System/Library/Frameworks/Network.framework"); then
    AC_MSG_RESULT(yes)
    AC_DEFINE(USE_NETWORKFMWK, 1, [enable Network.framework])
    ssl_msg="Network.framework"
    test network-framework != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
    NETWORKFRAMEWORK_ENABLED=1
    NETWORKFRAMEWORK_LDFLAGS='-framework Network -framework Security'
    LDFLAGS="$LDFLAGS $NETWORKFRAMEWORK_LDFLAGS"
    LDFLAGSPC="$LDFLAGSPC $NETWORKFRAMEWORK_LDFLAGS"
  else
    AC_MSG_RESULT(no)
  fi
  test -z "$ssl_msg" || ssl_backends="${ssl_backends:+$ssl_backends, }$ssl_msg"
else
  AC_MSG_RESULT(no)
fi

])