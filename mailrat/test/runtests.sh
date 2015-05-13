#!/bin/bash

prev=""
for test in `cd tests; ls -1 |sort -n`; do
  export MINDER_TOPIC_DEST=tests/${test}/topics
  if [ "${prev}" = "" ]; then
    export MINDER_TOPIC_SOURCE=${MINDER_TOPIC_DEST}
  else
    export MINDER_TOPIC_SOURCE=tests/${prev}/topics
  fi
  prev=${test}
  export MINDER_MAILDIR=tests/${test}/mail
  python ../scanner.py
done
  
