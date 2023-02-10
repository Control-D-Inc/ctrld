#!/bin/sh

set -ex

for dist_dir in ./dist/ctrld*; do
  upx --brute "${dist_dir}/ctrld"
done
