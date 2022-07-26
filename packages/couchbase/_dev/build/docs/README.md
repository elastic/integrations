# Couchbase Integration

This Elastic integration collects and parses the [Bucket](https://docs.couchbase.com/server/current/rest-api/rest-buckets-summary.html) metrics from [Couchbase](https://www.couchbase.com/) so that the user could monitor and troubleshoot the performance of the Couchbase instances.

This integration uses `http` metricbeat module to collect `bucket` metrics.

Note: For Couchbase cluster setup, there is an ideal scenario of single host with administrator access for the entire cluster to collect metrics. Providing multiple host from the same cluster might lead to data duplication. In case of multiple clusters, adding a new integration to collect data from different cluster host is a good option.

## Compatibility

This integration has been tested against Couchbase `v6.6`, `v7.0` and `v7.1`.

## Requirements

In order to ingest data from Couchbase, you must know the host(s) and the administrator credentials for the Couchbase instance(s).

Host Configuration Format: `http[s]://username:password@host:port`

Example Host Configuration: `http://Administrator:password@localhost:8091`

## Metrics

### Bucket

This is the `bucket` data stream. A bucket is a logical container for a related set of items such as key-value pairs or documents.

{{event "bucket"}}

{{fields "bucket"}}
