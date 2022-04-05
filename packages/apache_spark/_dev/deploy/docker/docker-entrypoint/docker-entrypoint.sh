#!/bin/bash

# shellcheck disable=SC1091

set -o errexit
set -o nounset
set -o pipefail
#set -o xtrace

# Load libraries
. /opt/bitnami/scripts/libbitnami.sh
. /opt/bitnami/scripts/libspark.sh

# Load Spark environment variables
eval "$(spark_env)"

print_welcome_page

if [ ! $EUID -eq 0 ] && [ -e "$LIBNSS_WRAPPER_PATH" ]; then
    echo "spark:x:$(id -u):$(id -g):Spark:$SPARK_HOME:/bin/false" > "$NSS_WRAPPER_PASSWD"
    echo "spark:x:$(id -g):" > "$NSS_WRAPPER_GROUP"
    echo "LD_PRELOAD=$LIBNSS_WRAPPER_PATH" >> "$SPARK_CONFDIR/spark-env.sh"
fi

if [[ "$1" = "/opt/bitnami/scripts/spark/run.sh" ]]; then
    info "** Starting Spark setup **"
    /opt/bitnami/scripts/spark/setup.sh 
    info "** Spark setup finished! **"
fi

eval "$(spark_env)"
cd /opt/bitnami/spark/sbin
./start-worker.sh $SPARK_MAIN_URL --cores $SPARK_WORKER_CORES --memory $SPARK_WORKER_MEMORY &
cd /opt/bitnami/spark/examples/src/main/python/
/opt/bitnami/spark/bin/spark-submit wordcount.py status_api_demo.py $SPARK_MAIN_URL &

echo ""
exec "$@"
