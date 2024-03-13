# Traefik Integration

This integration periodically fetches metrics from [Traefik](https://traefik.io/) servers. It also ingests access
logs created by the Traefik server.

## Compatibility

The Traefik datasets were tested with Traefik 1.6, 1.7 and 2.9.

## Logs

### Access Logs

The `access` data stream collects Traefik access logs.

An example event for `access` looks as following:

```json
{
    "@timestamp": "2024-02-09T11:53:32.609696286Z",
    "destination": {
        "address": "10.1.25.243",
        "ip": "10.1.25.243",
        "port": 80
    },
    "ecs": {
        "version": "8.5.1"
    },
    "event": {
        "category": [
            "web"
        ],
        "created": "2020-04-28T11:07:58.223Z",
        "duration": 59518533,
        "ingested": "2024-02-13T16:08:40.190327617Z",
        "kind": "event",
        "original": "{\"ClientAddr\": \"10.10.8.105:48376\",\"ClientHost\": \"103.250.14.10\",\"ClientPort\": \"48376\",\"ClientUsername\": \"-\",\"DownstreamContentSize\": 88,\"DownstreamStatus\": 200,\"Duration\": 59518533,\"OriginContentSize\": 88,\"OriginDuration\": 59428568,\"OriginStatus\": 200,\"Overhead\": 89965,\"RequestAddr\": \"api-students.unpad.ac.id\",\"RequestContentSize\": 0,\"RequestCount\": 75,\"RequestHost\": \"api-students.unpad.ac.id\",\"RequestMethod\": \"GET\",\"RequestPath\": \"/api/v1/study/140410210038/card/comment\",\"RequestPort\": \"-\",\"RequestProtocol\": \"HTTP/1.0\",\"RequestScheme\": \"http\",\"RetryAttempts\": 0,\"RouterName\": \"app-unpad-students-api-prod-app-unpad-students-api-api-students-unpad-ac-id-api@kubernetes\",\"ServiceAddr\": \"10.1.25.243:80\",\"ServiceName\": \"app-unpad-students-api-prod-app-unpad-students-api-80@kubernetes\",\"ServiceURL\": {\"Scheme\": \"http\",\"Opaque\": \"\",\"User\": null,\"Host\": \"10.1.25.243:80\",\"Path\": \"\",\"RawPath\": \"\",\"OmitHost\": false,\"ForceQuery\": false,\"RawQuery\": \"\",\"Fragment\": \"\",\"RawFragment\": \"\"},\"StartLocal\": \"2024-02-09T11:53:32.609696286Z\",\"StartUTC\": \"2024-02-09T11:53:32.609696286Z\",\"entryPointName\": \"web\",\"level\": \"info\",\"msg\": \"\",\"time\": \"2024-02-09T11:53:32Z\"}",
        "outcome": "success",
        "type": [
            "access"
        ]
    },
    "http": {
        "request": {
            "body": {
                "bytes": 0
            },
            "method": "GET"
        },
        "response": {
            "body": {
                "bytes": 88
            },
            "status_code": 200
        },
        "version": "1.0"
    },
    "log": {
        "level": "info"
    },
    "network": {
        "community_id": "1:Mgo2d5qbyedZ2JnxvcBh0BuPcWk=",
        "transport": "tcp"
    },
    "observer": {
        "egress": {
            "interface": {
                "name": "app-unpad-students-api-prod-app-unpad-students-api-80@kubernetes"
            }
        },
        "ingress": {
            "interface": {
                "name": "web"
            }
        },
        "product": "traefik",
        "type": "proxy",
        "vendor": "traefik"
    },
    "related": {
        "ip": [
            "10.10.8.105",
            "10.1.25.243"
        ]
    },
    "source": {
        "address": "10.10.8.105:48376",
        "ip": "10.10.8.105",
        "port": 48376
    },
    "tags": [
        "preserve_original_event"
    ],
    "traefik": {
        "access": {
            "origin": {
                "content_size": 88,
                "duration": 59428568,
                "status_code": 200
            },
            "overhead": 89965,
            "request_count": 75,
            "retry_attempts": 0,
            "router": {
                "name": "app-unpad-students-api-prod-app-unpad-students-api-api-students-unpad-ac-id-api@kubernetes"
            },
            "service": {
                "url": {
                    "domain": "10.1.25.243:80",
                    "force_query": false,
                    "fragment": "",
                    "opaque": "",
                    "path": "",
                    "raw_path": "",
                    "raw_query": "",
                    "user": null
                }
            }
        }
    },
    "url": {
        "domain": "api-students.unpad.ac.id",
        "original": "/api/v1/study/140410210038/card/comment",
        "scheme": "http"
    },
    "user": {
        "name": "-"
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| http.request.headers | The canonical headers of the monitored HTTP request. | object |
| http.response.headers | The canonical headers of the monitored HTTP request. | object |
| traefik.access.origin.content_size | The content length specified by the origin server, or 0 if unspecified. | long |
| traefik.access.origin.duration | The time taken (in nanoseconds) by the origin server ('upstream') to return its response. | long |
| traefik.access.origin.headers | The canonical headers of the monitored HTTP request. | object |
| traefik.access.origin.status_code | The HTTP status code returned by the origin server. If the request was handled by this Traefik instance (e.g. with a redirect), then this value will be absent (0). | long |
| traefik.access.origin.status_line | OriginStatus + Status code explanation | keyword |
| traefik.access.overhead | The processing time overhead (in nanoseconds) caused by Traefik | long |
| traefik.access.request_count | The number of requests received since the Traefik instance started. | long |
| traefik.access.retry_attempts | The amount of attempts the request was retried | long |
| traefik.access.router.name | The name of the Traefik router | keyword |
| traefik.access.service.address | The IP:port of the Traefik backend (extracted from ServiceURL) | keyword |
| traefik.access.service.duration | The name of the Traefik backend | long |
| traefik.access.service.url.domain |  | keyword |
| traefik.access.service.url.force_query | Traefik specific url field | boolean |
| traefik.access.service.url.fragment |  | keyword |
| traefik.access.service.url.opaque | Traefik specific url field | keyword |
| traefik.access.service.url.original | Traefik url as used in common log format | keyword |
| traefik.access.service.url.path |  | keyword |
| traefik.access.service.url.query |  | keyword |
| traefik.access.service.url.raw_path | Traefik specific url field | keyword |
| traefik.access.service.url.raw_query | Traefik specific url field | keyword |
| traefik.access.service.url.scheme |  | keyword |
| traefik.access.service.url.username |  | keyword |
| traefik.access.user_identifier | Is the RFC 1413 identity of the client | keyword |


## Metrics

### Health Metrics

The `health` data stream collects metrics from the Traefik server.

An example event for `health` looks as following:

```json
{
    "@timestamp": "2024-02-12T17:21:39.672Z",
    "agent": {
        "ephemeral_id": "63e0045d-0344-4bdb-9f94-26442e08d137",
        "id": "d95af4f5-ce65-45c7-8b0b-39929f004883",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.11.4"
    },
    "data_stream": {
        "dataset": "traefik.health",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "d95af4f5-ce65-45c7-8b0b-39929f004883",
        "snapshot": false,
        "version": "8.11.4"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "traefik.health",
        "duration": 1679238,
        "ingested": "2024-02-12T17:21:42Z",
        "module": "traefik"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "65c6e8a59cee4f20baaa9c3b45722316",
        "ip": "172.18.0.6",
        "mac": "02-42-AC-12-00-06",
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.15.0-92-generic",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "health",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service-traefik_format_common-1:8080/health",
        "name": "traefik",
        "type": "traefik"
    },
    "traefik": {
        "health": {
            "response": {
                "avg_time": {
                    "us": 826
                },
                "count": 16,
                "status_codes": {
                    "200": 16
                }
            },
            "uptime": {
                "sec": 17
            }
        }
    }
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |
| container.id | Unique container id. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.name | Name of the service data is collected from. The name of the service is normally user given. This allows for distributed services that run on multiple hosts to correlate the related instances based on the name. In the case of Elasticsearch the `service.name` could contain the cluster name. For Beats the `service.name` is by default a copy of the `service.type` field if no name is specified. | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |
| traefik.health.response.avg_time.us | Average response time in microseconds | long | gauge |
| traefik.health.response.count | Number of responses | long | counter |
| traefik.health.response.status_codes.\* | Number of responses per status code | object | counter |
| traefik.health.uptime.sec | Uptime of Traefik instance in seconds | long | gauge |

