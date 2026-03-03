#!/bin/sh

if [ "$IS_APM_VARIANT" == "true" ]
then
  while true
  do
    curl -X POST --data-binary "@./events.ndjson" http://beat:8200/intake/v2/events -H "Content-Type: application/x-ndjson"

    sleep 0.$((1 + $RANDOM % 9))
  done
fi
