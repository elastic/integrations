#!/bin/sh

#Sets a password for kibana_system user

set -e

until curl --request POST $ES_SERVICE_HOST/_security/user/kibana_system/_password \
  --user elastic:$ELASTIC_PASSWORD \
  --header 'Content-Type: application/json' \
  --data "{\"password\":\"$KIBANA_PASSWORD\"}"
do sleep 10; 
done;