# wait for the couchbase-server starts
until curl -f  http://Administrator:password@localhost:8091/pools/default
do
  sleep 5s
done

# add "beer-sample" bucket from sampleBuckets
curl -v -u Administrator:password -X POST http://127.0.0.1:8091/sampleBuckets/install -d '["beer-sample"]'

# using couchbase-cli run xdcr-setup for the cluster
couchbase-cli xdcr-setup -c 127.0.0.1 -u Administrator -p password --create --xdcr-cluster-name cluster --xdcr-hostname 127.0.0.1 --xdcr-username Administrator --xdcr-password password

# wait till the xdcr-setup creates cluster
until curl -f  http://Administrator:password@localhost:8091/pools/default/buckets/beer-sample/stats
do
  sleep 5s
done

# perform replication from "beer-sample" to "travel-sample"
curl -v -X POST -u Administrator:password http://127.0.0.1:8091/controller/createReplication -d fromBucket=beer-sample -d toCluster=cluster -d toBucket=travel-sample -d replicationType=continuous -d enableCompression=1
