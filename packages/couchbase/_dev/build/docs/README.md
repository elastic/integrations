# Couchbase Integration

This Elastic integration collects and parses the [Bucket](https://docs.couchbase.com/server/current/rest-api/rest-buckets-summary.html) metrics from [Couchbase](https://www.couchbase.com/) so that the user could monitor and troubleshoot the performance of the Couchbase instances.

This integration uses `http` metricbeat module to collect above metrics.

## Compatibility

This integration has been tested against Couchbase `v6.6`, `v7.0` and `v7.1`.

## Requirements

In order to ingest data from Couchbase, you must know the host(s) and the administrator credentials for the Couchbase instance(s).

Host Configuration Format: `http[s]://username:password@host:port`

Example Host Configuration: `http://Administrator:password@localhost:8091`

## Metrics

### Bucket

This is the `bucket` data stream.

{{event "bucket"}}

{{fields "bucket"}}
