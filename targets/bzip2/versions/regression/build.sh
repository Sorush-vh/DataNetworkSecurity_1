#!/bin/sh
# Regression scenario: the build configuration accidentally disables PIE.
# The hardening comparison must report this as an unexpected protection change.
set -eu
CFLAGS="${CFLAGS:--O2} -fstack-protector-strong -fno-PIE"
LDFLAGS="${LDFLAGS:-} -no-pie -Wl,-z,relro,-z,now"
exec make CC="${CC:-gcc}" CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS" bzip2
