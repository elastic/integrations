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

An example event for `server` looks as following:

```json
{
    "@timestamp": "2022-07-13T07:21:10.000Z",
    "agent": {
        "ephemeral_id": "389401b4-5960-4cd8-a207-033a7e3c5a54",
        "id": "1f5b14b7-019a-4625-85ab-1b51ea6c08e5",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.3.2"
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
                    "get": 1,
                    "head": 0,
                    "post": 0,
                    "put": 0
                },
                "requests": {
                    "bulk": 0,
                    "count": 1
                },
                "status_codes": {
                    "200": 1,
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
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "1f5b14b7-019a-4625-85ab-1b51ea6c08e5",
        "snapshot": false,
        "version": "8.3.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "couchdb.server",
        "duration": 6178377,
        "ingested": "2022-07-13T07:21:14Z",
        "kind": "metric",
        "module": "couchdb",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.18.0.7"
        ],
        "mac": [
            "02:42:ac:12:00:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.66.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "json",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service_couchdb_1:5984/_node/_local/_stats",
        "type": "http"
    },
    "tags": [
        "couchdb-server"
    ]
}
```

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

