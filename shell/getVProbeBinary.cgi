#!/bin/bash 

source /usr/local/var/chkdef.sh

echo "HTTP/1.0 200 OK"
echo "Content-type: application/octet-stream"
echo ""

cat /data/kpi/vprobes/vprobe
