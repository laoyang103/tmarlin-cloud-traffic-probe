#!/bin/bash

export LANG="en_US.UTF-8"
VP_LOG_DIR="/data/kpi/vprobes/"

if [ "$REQUEST_METHOD" = "POST" ]; then
  user=`echo $QUERY_STRING | awk -F "&" '{print $1}' | awk -F "=" '{print $2}'`
  fname=`echo $QUERY_STRING | awk -F "&" '{print $2}' | awk -F "=" '{print $2}'`
  userdir=$VP_LOG_DIR"/"$user
  test ! -e $userdir && mkdir -p $userdir
  cat > $userdir"/"$fname
fi
