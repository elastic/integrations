#!/bin/bash

ADMIN_USER="Administrator"
ADMIN_PASSWORD="password"
CB_HOST="localhost"
CB_PORT="8091"
BUCKET_NAME="beer-sample"
XDCR_CLUSTER_NAME="cluster"
REPLICATION_TO_BUCKET="travel-sample"

# wait for the couchbase-server starts
is_couchbase_ready() {
  until curl -s -f http://$ADMIN_USER:$ADMIN_PASSWORD@$CB_HOST:$CB_PORT/pools/default >/dev/null 2>&1; do
    sleep 5s
  done
}
is_couchbase_ready

# adds a Couchbase sample bucket using the provided BUCKET_NAME variable
add_cb_sample_bucket() {
  http_code=$(curl -s -o /dev/null -w "%{http_code}" \
    --user "${ADMIN_USER}:${ADMIN_PASSWORD}" \
    --header "Content-Type: application/json" \
    --request POST \
    --data "[\"${BUCKET_NAME}\"]" \
    "http://${CB_HOST}:${CB_PORT}/sampleBuckets/install")

  if [[ "${http_code}" -eq 202 ]]; then
    return 0
  else
    return 1
  fi
}

# Loop until the sample bucket is successfully added
while ! add_cb_sample_bucket; do
  sleep 5
done

# using couchbase-cli run xdcr-setup for the cluster
couchbase-cli xdcr-setup -c $CB_HOST -u $ADMIN_USER -p $ADMIN_PASSWORD --create --xdcr-cluster-name $XDCR_CLUSTER_NAME --xdcr-hostname $CB_HOST --xdcr-username $ADMIN_USER --xdcr-password $ADMIN_PASSWORD

# wait till the "beer-sample" bucket is ready
until [ "$(curl -s -w '%{http_code}' -o /dev/null "http://$ADMIN_USER:$ADMIN_PASSWORD@$CB_HOST:$CB_PORT/pools/default/buckets/$BUCKET_NAME/stats")" -eq 200 ]; do
  sleep 5s
done

# perform replication from "beer-sample" to "travel-sample"
curl -v -X POST -u $ADMIN_USER:$ADMIN_PASSWORD http://$CB_HOST:$CB_PORT/controller/createReplication -d fromBucket=$BUCKET_NAME -d toCluster=$XDCR_CLUSTER_NAME -d toBucket=$REPLICATION_TO_BUCKET -d replicationType=continuous -d enableCompression=1
