#!/bin/sh

# Makes requests to kibana API so that audit logs can be generated
set -e

# Copy the log files content from this container to /var/log/ which is a bind mounted to ${SERVICE_LOGS_DIR}
# This sh must be executed by a root user in order to have permission to write in the ${SERVICE_LOGS_DIR} folder
copy_log_files () {
  for f in /kbn_logs/*;
  do
    echo "Copy ${f##*/} file..."

    if [[ ! -e /var/log/${f##*/} ]]; then
      touch /var/log/${f##*/}
    fi

    ## appends only new lines
    comm -23 "$f" /var/log/${f##*/} >> /var/log/${f##*/}
  done
}

attempt_counter=0
max_attempts=6

until curl -s --request GET \
  --url $KIBANA_SERVICE_HOST/login \
  --user "elastic:$KIBANA_PASSWORD" \
  --header 'Content-Type: application/json'
do

  if [ ${attempt_counter} -eq ${max_attempts} ];then
    echo "Max attempts reached"
    exit 1
  fi

  printf '.'
  attempt_counter=$(($attempt_counter+1))
  sleep 10
done

while true
do
  curl -s --request GET \
    --url $KIBANA_SERVICE_HOST/api/features \
    --user "elastic:$KIBANA_PASSWORD" \
    --header 'Content-Type: application/json'

  echo "Audit log created"

  copy_log_files

  sleep 10
done