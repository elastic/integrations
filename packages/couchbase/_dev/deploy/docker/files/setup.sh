# wait for the couchbase-server starts
until curl -f  http://Administrator:password@localhost:8091/pools/default
do
  sleep 5s
done

# add "beer-sample" bucket from sampleBuckets
until [ "$(curl -v -u Administrator:password -X POST http://localhost:8091/sampleBuckets/install -d '["beer-sample"]' -o /dev/null -w '%{http_code}')" -eq 202 ]
do
  sleep 5s
done

# using couchbase-cli run xdcr-setup for the cluster
couchbase-cli xdcr-setup -c 127.0.0.1 -u Administrator -p password --create --xdcr-cluster-name cluster --xdcr-hostname 127.0.0.1 --xdcr-username Administrator --xdcr-password password

# wait till the "beer-sample" bucket is ready
until [ "$(curl -s -w '%{http_code}' -o /dev/null "http://Administrator:password@localhost:8091/pools/default/buckets/beer-sample/stats")" -eq 200 ]
do
  sleep 5s
done

# perform replication from "beer-sample" to "travel-sample"
curl -v -X POST -u Administrator:password http://127.0.0.1:8091/controller/createReplication -d fromBucket=beer-sample -d toCluster=cluster -d toBucket=travel-sample -d replicationType=continuous -d enableCompression=1
