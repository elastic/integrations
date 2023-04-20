#!/bin/sh

#Sets a password for kibana_system user
attempt_counter=0
max_attempts=6

until curl -s --request POST $ES_SERVICE_HOST/_security/user/kibana_system/_password \
  --user "elastic:$ELASTIC_PASSWORD" \
  --header 'Content-Type: application/json' \
  --data "{\"password\":\"$KIBANA_PASSWORD\"}" 
do 
  if [ ${attempt_counter} -eq ${max_attempts} ];then
    echo "Max attempts reached"
    exit 1
  fi

  printf '.'
  attempt_counter=$(($attempt_counter+1))
  sleep 10
done

echo "Setup complete"