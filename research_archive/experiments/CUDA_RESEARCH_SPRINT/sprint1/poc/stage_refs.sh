#!/bin/bash
set -x
R=/home/pocdev/gpuvulnagent-worker/refs
W=/mnt/f/qcx/code/GPUVulnAgent/runs-sprint/trial0/session/run/workspace
mkdir -p $W/refs
find $R/cuobjdump-12-8-12.8.55-1 $R/cuobjdump-13-0-13.0.85-1 -type f | head -50
for d in cuobjdump-12-8-12.8.55-1 cuobjdump-13-0-13.0.85-1 nvdisasm-13-0-13.0.85-1; do
  cp -a $R/$d $W/refs/ 2>/dev/null
done
ls -laR $W/refs | head -60