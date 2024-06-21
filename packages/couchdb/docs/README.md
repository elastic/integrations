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
        "version": "8.5.1"
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| error.message | Error message. | match_only_text |  |  |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |  |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |  |  |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |  |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |  |  |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |

