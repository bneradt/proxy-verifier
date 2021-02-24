#!/bin/bash
#
# Build quic/HTTP3 library dependencies.
#
# Copyright 2021, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

# Inspired by:
# https://github.com/curl/curl/blob/master/docs/HTTP3.md

fail()
{
  echo $1
  exit 1
}

[ $# -eq 1 ] || fail "Please provide a directory in which to build the custom curl."
topdir=$1
mkdir -p ${topdir}
ls -1qA ${topdir} | grep -q . && fail "${topdir} is not empty."

# 1. OpenSSL version that supports quic.
cd ${topdir}
git clone --depth 1 -b OpenSSL_1_1_1g-quic-draft-28 https://github.com/tatsuhiro-t/openssl
cd openssl
./config enable-tls1_3 --prefix=${topdir}/openssl_build
make -j4
make install_sw

# 2. nghttp3
cd ${topdir}
git clone https://github.com/ngtcp2/nghttp3
cd nghttp3/
autoreconf -i
./configure --prefix=${topdir}/nghttp3_build --enable-lib-only
make -j4
make install

# 3. ngtcp2
cd ${topdir}
git clone https://github.com/ngtcp2/ngtcp2
cd ngtcp2
autoreconf -i
./configure \
  PKG_CONFIG_PATH=${topdir}/openssl_build/lib/pkgconfig:${topdir}/nghttp3_build/lib/pkgconfig \
  LDFLAGS="-Wl,-rpath,${topdir}/openssl_build/lib" \
  --prefix=${topdir}/ngtcp2_build \
  --enable-lib-only
make -j4
make install
