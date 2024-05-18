ADMIN_USER="Administrator"
ADMIN_PASSWORD="password"
CB_HOST="localhost"
CB_PORT="8091"
BUCKET_NAME="beer-sample"
XDCR_CLUSTER_NAME="cluster"
REPLICATION_TO_BUCKET="travel-sample"

# wait for the couchbase-server starts
until curl -f  http://$ADMIN_USER:$ADMIN_PASSWORD@$CB_HOST:$CB_PORT/pools/default
do
  sleep 5s
done

# wait till "beer-sample" bucket is added from sampleBuckets
until [ "$(curl -v -u $ADMIN_USER:$ADMIN_PASSWORD -X POST http://$CB_HOST:$CB_PORT/sampleBuckets/install -d "[\"$BUCKET_NAME\"]" -o /dev/null -w '%{http_code}')" -eq 202 ]
do
  sleep 5s
done

# using couchbase-cli run xdcr-setup for the cluster
couchbase-cli xdcr-setup -c $CB_HOST -u $ADMIN_USER -p $ADMIN_PASSWORD --create --xdcr-cluster-name $XDCR_CLUSTER_NAME --xdcr-hostname $CB_HOST --xdcr-username $ADMIN_USER --xdcr-password $ADMIN_PASSWORD

# wait till the "beer-sample" bucket is ready
until [ "$(curl -s -w '%{http_code}' -o /dev/null "http://$ADMIN_USER:$ADMIN_PASSWORD@$CB_HOST:$CB_PORT/pools/default/buckets/$BUCKET_NAME/stats")" -eq 200 ]
do
  sleep 5s
done

# perform replication from "beer-sample" to "travel-sample"
curl -v -X POST -u $ADMIN_USER:$ADMIN_PASSWORD http://$CB_HOST:$CB_PORT/controller/createReplication -d fromBucket=$BUCKET_NAME -d toCluster=$XDCR_CLUSTER_NAME -d toBucket=$REPLICATION_TO_BUCKET -d replicationType=continuous -d enableCompression=1