#!/bin/sh

# Makes requests to kibana API so that audit logs can be generated

set -e

until curl --request GET \
    --user "elastic:$KIBANA_PASSWORD" \
    --url $KIBANA_SERVICE_HOST/login  \
    --header 'Content-Type: application/json'
do sleep 10;
done;

while true
do
  echo Generating audit logs

  curl --request GET \
    --user "elastic:$KIBANA_PASSWORD" \
    --url $KIBANA_SERVICE_HOST/api/features  \
    --header 'Content-Type: application/json'

  sleep 10
done;