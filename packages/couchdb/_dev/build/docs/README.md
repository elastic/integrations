# CouchDB Integration

This Elastic integration collects and parses the Server metrics from [CouchDB](https://couchdb.apache.org/) so that the user could monitor and troubleshoot the performance of the CouchDB instances.

This integration uses `http` metricbeat module to collect above metrics.

## Compatibility

This integration has been tested against `CouchDB version 3.1` and `CouchDB version 3.2.2`.

## Requirements

In order to ingest data from CouchDB, you must know the host(s) and the administrator credentials for the CouchDB instance(s).

Host Configuration Format: `http[s]://username:password@host:port`

Example Host Configuration: `http://admin:changeme@localhost:5984`

## Metrics

### Server

This is the `server` data stream.

Reference: https://docs.couchdb.org/en/stable/api/server/common.html#node-node-name-stats

{{event "server"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "server"}}
