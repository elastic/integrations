# CouchDB Integration

This Elastic integration collects and parses the Server metrics from [CouchDB](https://couchdb.apache.org/) so that the user could monitor and troubleshoot the performance of the CouchDB instances.

This integration uses `http` metricbeat module to collect above metrics.

## Compatibility

This integration has been tested against `CouchDB version 3.1.2`, `CouchDB version 3.2.2` and `CouchDB version 3.5.1`.

## Requirements

In order to ingest data from CouchDB, you must know the host(s) and the administrator credentials for the CouchDB instance(s).

Host Configuration Format: `http[s]://username:password@host:port`

Example Host Configuration: `http://admin:changeme@localhost:5984`

> Note: To mask the password in the Hosts connection string, remove the username and password from the string. Then, set up the Hosts field with only the host address (`localhost:5984` in the example) and any additional connection parameters. Finally, use the `username` and `password` fields under advanced options for configuration.

## Metrics

### Server

This is the `server` data stream.

Reference: https://docs.couchdb.org/en/stable/api/server/common.html#node-node-name-stats

An example event for `server` looks as following:

```json
{
    "@timestamp": "2026-05-19T22:24:35.048Z",
    "agent": {
        "ephemeral_id": "fe500f9f-556d-4d54-bb10-d3c97c42deef",
        "id": "603c921f-4aec-431b-95e7-70941af02e0f",
        "name": "elastic-agent-44591",
        "type": "metricbeat",
        "version": "9.4.1"
    },
    "couchdb": {
        "server": {
            "auth_cache": {
                "hits": 0,
                "misses": 0
            },
            "database": {
                "open": 0,
                "reads": 0,
                "writes": 0
            },
            "httpd": {
                "clients_requesting_changes": 0,
                "request_methods": {
                    "copy": 0,
                    "delete": 0,
                    "get": 3,
                    "head": 0,
                    "post": 0,
                    "put": 0
                },
                "requests": {
                    "bulk": 0,
                    "count": 2
                },
                "status_codes": {
                    "200": 2,
                    "201": 0,
                    "202": 0,
                    "301": 0,
                    "304": 0,
                    "400": 0,
                    "401": 0,
                    "403": 0,
                    "404": 0,
                    "405": 0,
                    "409": 0,
                    "412": 0,
                    "500": 0
                },
                "view_reads": {
                    "count": 0,
                    "temporary": 0
                }
            },
            "open_os_files": 0,
            "request_time": {
                "avg": 0
            }
        }
    },
    "data_stream": {
        "dataset": "couchdb.server",
        "namespace": "97388",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "603c921f-4aec-431b-95e7-70941af02e0f",
        "snapshot": true,
        "version": "9.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "couchdb.server",
        "duration": 132409458,
        "ingested": "2026-05-19T22:24:36Z",
        "kind": "metric",
        "module": "couchdb",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-44591",
        "ip": [
            "172.18.0.4",
            "172.19.0.2"
        ],
        "mac": [
            "16-AD-61-96-55-44",
            "A2-B3-5B-02-EF-A1"
        ],
        "name": "elastic-agent-44591",
        "os": {
            "kernel": "6.8.0-64-generic",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "metricset": {
        "name": "json",
        "period": 10000
    },
    "service": {
        "address": "http://svc-couchdb:5984/_node/_local/_stats",
        "type": "http"
    },
    "tags": [
        "couchdb-server"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| couchdb.server.auth_cache.hits | Number of authentication cache hits. | long |  | counter |
| couchdb.server.auth_cache.misses | Number of authentication cache misses. | long |  | counter |
| couchdb.server.database.open | Number of open databases. | long |  | counter |
| couchdb.server.database.reads | Number of times a document was read from a database. | long |  | counter |
| couchdb.server.database.writes | Number of times a database was changed. | long |  | counter |
| couchdb.server.httpd.clients_requesting_changes | Number of clients for continuous changes. | long |  | counter |
| couchdb.server.httpd.request_methods.copy | Number of HTTP COPY requests. | long |  | counter |
| couchdb.server.httpd.request_methods.delete | Number of HTTP DELETE requests. | long |  | counter |
| couchdb.server.httpd.request_methods.get | Number of HTTP GET requests. | long |  | counter |
| couchdb.server.httpd.request_methods.head | Number of HTTP HEAD requests. | long |  | counter |
| couchdb.server.httpd.request_methods.post | Number of HTTP POST requests. | long |  | counter |
| couchdb.server.httpd.request_methods.put | Number of HTTP PUT requests. | long |  | counter |
| couchdb.server.httpd.requests.bulk | Number of bulk requests. | long |  | counter |
| couchdb.server.httpd.requests.count | Number of HTTP requests. | long |  | counter |
| couchdb.server.httpd.status_codes.200 | Number of HTTP 200 OK responses. | long |  | counter |
| couchdb.server.httpd.status_codes.201 | Number of HTTP 201 Created responses. | long |  | counter |
| couchdb.server.httpd.status_codes.202 | Number of HTTP 202 Accepted responses. | long |  | counter |
| couchdb.server.httpd.status_codes.301 | Number of HTTP 301 Moved Permanently responses. | long |  | counter |
| couchdb.server.httpd.status_codes.304 | Number of HTTP 304 Not Modified responses. | long |  | counter |
| couchdb.server.httpd.status_codes.400 | Number of HTTP 400 Bad Request responses. | long |  | counter |
| couchdb.server.httpd.status_codes.401 | Number of HTTP 401 Unauthorized responses. | long |  | counter |
| couchdb.server.httpd.status_codes.403 | Number of HTTP 403 Forbidden responses. | long |  | counter |
| couchdb.server.httpd.status_codes.404 | Number of HTTP 404 Not Found responses. | long |  | counter |
| couchdb.server.httpd.status_codes.405 | Number of HTTP 405 Method Not Allowed responses. | long |  | counter |
| couchdb.server.httpd.status_codes.409 | Number of HTTP 409 Conflict responses. | long |  | counter |
| couchdb.server.httpd.status_codes.412 | Number of HTTP 412 Precondition Failed responses. | long |  | counter |
| couchdb.server.httpd.status_codes.500 | Number of HTTP 500 Internal Server Error responses. | long |  | counter |
| couchdb.server.httpd.view_reads.count | Number of view reads. | long |  | counter |
| couchdb.server.httpd.view_reads.temporary | Number of temporary view reads. | long |  | counter |
| couchdb.server.open_os_files | Number of file descriptors CouchDB has open. | long |  | counter |
| couchdb.server.request_time.avg | Arithmetic mean of the request time inside CouchDB. | float | s |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |

