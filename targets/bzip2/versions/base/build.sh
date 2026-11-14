#!/bin/sh
# Build bzip2 with the profile flags supplied by the execution harness.
# Hardening flags are appended so the release binary can be inspected.
set -eu
CFLAGS="${CFLAGS:--O2} -fstack-protector-strong -fPIE"
LDFLAGS="${LDFLAGS:-} -pie -Wl,-z,relro,-z,now"
exec make CC="${CC:-gcc}" CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS" bzip2
