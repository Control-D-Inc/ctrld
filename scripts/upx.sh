#!/bin/sh

set -ex

binary=$1

if [ -z "$binary" ]; then
  echo >&2 "Usage: $0 <binary>"
  exit 1
fi

case "$binary" in
  *_freebsd_*)
    echo >&2 "upx does not work with freebsd binary yet"
    exit 0
    ;;
  *_windows_arm*)
    echo >&2 "upx does not work with windows arm/arm64 binary yet"
    exit 0
    ;;
esac

upx -- "$binary"
