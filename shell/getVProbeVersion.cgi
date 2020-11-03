#!/bin/bash 

source /usr/local/var/chkdef.sh

echo "HTTP/1.0 200 OK"
echo "Content-Type: text/html"
echo ""

/data/kpi/vprobes/vprobe -h | grep version
