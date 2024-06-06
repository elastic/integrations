# CouchDB Integration

This Elastic integration collects and parses the Server metrics from [CouchDB](https://couchdb.apache.org/) so that the user could monitor and troubleshoot the performance of the CouchDB instances.

This integration uses `http` metricbeat module to collect above metrics.

## Compatibility

This integration has been tested against `CouchDB version 3.1` and `CouchDB version 3.2.2`.

## Requirements

In order to ingest data from CouchDB, you must know the host(s) and the administrator credentials for the CouchDB instance(s).

Host Configuration Format: `http[s]://username:password@host:port`

Example Host Configuration: `http://admin:changeme@localhost:5984`

> Note: To mask the password shown in the Hosts connection string, remove the username and password from the string, and configure the Hosts to only include the host address(`localhost:5984` in the example) and any additional parameters required for the connection. Subsquently, use the `username` and `password` fields under advanced options to configure them.

## Metrics

### Server

This is the `server` data stream.

Reference: https://docs.couchdb.org/en/stable/api/server/common.html#node-node-name-stats

{{event "server"}}

{{fields "server"}}
