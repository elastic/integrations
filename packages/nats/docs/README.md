# NATS integration

This integration is used to collect logs and metrics from [NATS servers](https://nats.io/).
The integration collects metrics from [NATS monitoring server APIs](https://nats.io/documentation/managing_the_server/monitoring/).


## Compatibility

The Nats package is tested with Nats 1.3.0, 2.0.4 and 2.1.4

## Logs

### log

The `log` dataset collects the NATS logs.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2020-11-25T11:50:17.759Z",
    "agent": {
        "ephemeral_id": "4f1426bb-db10-4b5d-9e1c-ba6da401dc34",
        "hostname": "5706c620a165",
        "id": "25c804ef-d8c8-4a2e-9228-64213daef566",
        "name": "5706c620a165",
        "type": "filebeat",
        "version": "7.11.0"
    },
    "client": {
        "ip": "192.168.192.3",
        "port": 53482
    },
    "data_stream": {
        "dataset": "nats.log",
        "namespace": "default",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "5a7b52c1-66ae-47ce-ad18-70dadf1bedfa",
        "snapshot": true,
        "version": "7.11.0"
    },
    "event": {
        "created": "2020-11-25T11:53:04.192Z",
        "dataset": "nats.log",
        "ingested": "2020-11-25T11:53:10.021181400Z",
        "kind": "event",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "5706c620a165",
        "id": "06c26569966fd125c15acac5d7feffb6",
        "ip": [
            "192.168.192.8"
        ],
        "mac": [
            "02:42:c0:a8:c0:08"
        ],
        "name": "5706c620a165",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "4.9.184-linuxkit",
            "name": "CentOS Linux",
            "platform": "centos",
            "version": "7 (Core)"
        }
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/var/log/nats/nats.log"
        },
        "level": "trace",
        "offset": 36865655
    },
    "nats": {
        "log": {
            "client": {
                "id": "86"
            },
            "msg": {
                "type": "payload"
            }
        }
    },
    "network": {
        "direction": "inbound"
    },
    "process": {
        "pid": 6
    },
    "related": {
        "ip": [
            "192.168.192.3"
        ]
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
| input.type | Type of Filebeat input. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| nats.log.client.id | The id of the client | integer |
| nats.log.msg.bytes | Size of the payload in bytes | long |
| nats.log.msg.error.message | Details about the error occurred | text |
| nats.log.msg.max_messages | An optional number of messages to wait for before automatically unsubscribing | integer |
| nats.log.msg.queue_group | The queue group which subscriber will join | text |
| nats.log.msg.reply_to | The inbox subject on which the publisher is listening for responses | keyword |
| nats.log.msg.sid | The unique alphanumeric subscription ID of the subject | integer |
| nats.log.msg.subject | Subject name this message was received on | keyword |
| nats.log.msg.type | The protocol message type | keyword |


## Metrics

The default datasets are `stats`, `connections`, `routes` and `subscriptions` while `connection` and `route`
datasets can be enabled to collect detailed metrics per connection/route.

### stats

This is the `stats` dataset of the Nats package, in charge of retrieving generic
metrics from a Nats instance.


An example event for `stats` looks as following:

```json
{
    "@timestamp": "2022-01-12T02:55:11.384Z",
    "agent": {
        "ephemeral_id": "259312b7-26e3-4a70-8c3a-720386a6a71e",
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "nats.stats",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "nats.stats",
        "duration": 49665904,
        "ingested": "2022-01-12T02:55:14Z",
        "module": "nats"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "4ccba669f0df47fa3f57a9e4169ae7f1",
        "ip": [
            "172.18.0.4"
        ],
        "mac": [
            "02:42:ac:12:00:04"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "5.11.0-44-generic",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "metricset": {
        "name": "stats",
        "period": 10000
    },
    "nats": {
        "server": {
            "id": "NCXFULRLCZMWAWXMVPHIAESOUAOURC2INJOQFODIMJ2IHZ3QE7BH7X74",
            "time": "2022-01-12T02:55:11.384194105Z"
        },
        "stats": {
            "cores": 1,
            "cpu": 0.28,
            "http": {
                "req_stats": {
                    "uri": {
                        "connz": 0,
                        "root": 0,
                        "routez": 0,
                        "subsz": 0,
                        "varz": 2
                    }
                }
            },
            "in": {
                "bytes": 13072240,
                "messages": 817015
            },
            "mem": {
                "bytes": 12103680
            },
            "out": {
                "bytes": 0,
                "messages": 0
            },
            "remotes": 1,
            "slow_consumers": 0,
            "total_connections": 1,
            "uptime": 23
        }
    },
    "service": {
        "address": "http://elastic-package-service-nats-1:8222/varz",
        "type": "nats"
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
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |
| nats.server.id | The server ID | keyword |  |
| nats.server.time | Server time of metric creation | date |  |
| nats.stats.cores | The number of logical cores the NATS process runs on | integer | gauge |
| nats.stats.cpu | The current cpu usage of NATs process | scaled_float | gauge |
| nats.stats.http.req_stats.uri.connz | The number of hits on connz monitoring uri | long | counter |
| nats.stats.http.req_stats.uri.root | The number of hits on root monitoring uri | long | counter |
| nats.stats.http.req_stats.uri.routez | The number of hits on routez monitoring uri | long | counter |
| nats.stats.http.req_stats.uri.subsz | The number of hits on subsz monitoring uri | long | counter |
| nats.stats.http.req_stats.uri.varz | The number of hits on varz monitoring uri | long | counter |
| nats.stats.in.bytes | The amount of incoming bytes | long | counter |
| nats.stats.in.messages | The amount of incoming messages | long | counter |
| nats.stats.mem.bytes | The current memory usage of NATS process | long | gauge |
| nats.stats.out.bytes | The amount of outgoing bytes | long | counter |
| nats.stats.out.messages | The amount of outgoing messages | long | counter |
| nats.stats.remotes | The number of registered remotes | integer | gauge |
| nats.stats.slow_consumers | The number of slow consumers currently on NATS | long | gauge |
| nats.stats.total_connections | The number of totally created clients | long | counter |
| nats.stats.uptime | The period the server is up (sec) | long | counter |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |


### connections

This is the `connections` dataset of the Nats package, in charge of retrieving generic
metrics about connections from a Nats instance.

An example event for `connections` looks as following:

```json
{
    "@timestamp": "2022-01-12T02:46:48.367Z",
    "agent": {
        "ephemeral_id": "3886806d-b880-4842-a4be-79391a8fc2e4",
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "nats.connections",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "nats.connections",
        "duration": 125128016,
        "ingested": "2022-01-12T02:46:50Z",
        "module": "nats"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "4ccba669f0df47fa3f57a9e4169ae7f1",
        "ip": [
            "172.18.0.4"
        ],
        "mac": [
            "02:42:ac:12:00:04"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "5.11.0-44-generic",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "metricset": {
        "name": "connections",
        "period": 10000
    },
    "nats": {
        "connections": {
            "total": 1
        },
        "server": {
            "id": "NBBIEC4H2KI3XR4SUAATGL5INXZZS72ZUYMVJBCLKVDDEWCJCFZOXH7W",
            "time": "2022-01-12T02:46:48.367495135Z"
        }
    },
    "service": {
        "address": "http://elastic-package-service-nats-1:8222/connz",
        "type": "nats"
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
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |
| nats.connections.total | The number of currently active clients | integer | gauge |
| nats.server.id | The server ID | keyword |  |
| nats.server.time | Server time of metric creation | date |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |


### routes

This is the `routes` dataset of the Nats package, in charge of retrieving generic
metrics about routes from a Nats instance.

An example event for `routes` looks as following:

```json
{
    "@timestamp": "2022-01-12T02:52:26.015Z",
    "agent": {
        "ephemeral_id": "5ca072d2-2eac-4cad-9a39-bdfec64f2640",
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "nats.routes",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "nats.routes",
        "duration": 29566227,
        "ingested": "2022-01-12T02:52:29Z",
        "module": "nats"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "4ccba669f0df47fa3f57a9e4169ae7f1",
        "ip": [
            "172.18.0.4"
        ],
        "mac": [
            "02:42:ac:12:00:04"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "5.11.0-44-generic",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "metricset": {
        "name": "routes",
        "period": 10000
    },
    "nats": {
        "routes": {
            "total": 1
        },
        "server": {
            "id": "NAGYMNF4IADKFHPNJEJMQUWPYUVOWX3KC3V2UINL5QJYDVGIAZB7N3L6",
            "time": "2022-01-12T02:52:26.015311657Z"
        }
    },
    "service": {
        "address": "http://elastic-package-service-nats-1:8222/routez",
        "type": "nats"
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
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |
| nats.routes.total | The number of registered routes | integer | gauge |
| nats.server.id | The server ID | keyword |  |
| nats.server.time | Server time of metric creation | date |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |


### subscriptions

This is the `subscriptions` dataset of the Nats package, in charge of retrieving
metrics about subscriptions from a Nats instance.

An example event for `subscriptions` looks as following:

```json
{
    "@timestamp": "2022-01-12T02:57:55.837Z",
    "agent": {
        "ephemeral_id": "29d75d7c-e650-4bf4-ba7a-f769e4edd5da",
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "nats.subscriptions",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "nats.subscriptions",
        "duration": 11100010,
        "ingested": "2022-01-12T02:57:59Z",
        "module": "nats"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "4ccba669f0df47fa3f57a9e4169ae7f1",
        "ip": [
            "172.18.0.4"
        ],
        "mac": [
            "02:42:ac:12:00:04"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "5.11.0-44-generic",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "metricset": {
        "name": "subscriptions",
        "period": 10000
    },
    "nats": {
        "subscriptions": {
            "cache": {
                "fanout": {
                    "avg": 0,
                    "max": 0
                },
                "hit_rate": 0,
                "size": 1
            },
            "inserts": 0,
            "matches": 1,
            "removes": 0,
            "total": 0
        }
    },
    "service": {
        "address": "http://elastic-package-service-nats-1:8222/subsz",
        "type": "nats"
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
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |
| nats.server.id | The server ID | keyword |  |
| nats.server.time | Server time of metric creation | date |  |
| nats.subscriptions.cache.fanout.avg | The average fanout served by cache | double | gauge |
| nats.subscriptions.cache.fanout.max | The maximum fanout served by cache | integer | gauge |
| nats.subscriptions.cache.hit_rate | The rate matches are being retrieved from cache | scaled_float | gauge |
| nats.subscriptions.cache.size | The number of result sets in the cache | integer | gauge |
| nats.subscriptions.inserts | The number of insert operations in subscriptions list | long | counter |
| nats.subscriptions.matches | The number of times a match is found for a subscription | long | counter |
| nats.subscriptions.removes | The number of remove operations in subscriptions list | long | counter |
| nats.subscriptions.total | The number of active subscriptions | integer | gauge |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |


### connection

This is the `connection` dataset of the Nats package, in charge of retrieving detailed
metrics per connection from a Nats instance.

An example event for `connection` looks as following:

```json
{
    "@timestamp": "2022-01-12T02:43:51.172Z",
    "agent": {
        "ephemeral_id": "3cf8068e-3998-4da7-b2f1-de14207c5d44",
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "nats.connection",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "nats.connection",
        "duration": 276175024,
        "ingested": "2022-01-12T02:43:52Z",
        "module": "nats"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "4ccba669f0df47fa3f57a9e4169ae7f1",
        "ip": [
            "172.18.0.4"
        ],
        "mac": [
            "02:42:ac:12:00:04"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "5.11.0-44-generic",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "metricset": {
        "name": "connection",
        "period": 10000
    },
    "nats": {
        "connection": {
            "idle_time": 0,
            "in": {
                "bytes": 10310992,
                "messages": 644437
            },
            "name": "NATS Benchmark",
            "out": {
                "bytes": 0,
                "messages": 0
            },
            "pending_bytes": 0,
            "subscriptions": 0,
            "uptime": 24
        },
        "server": {
            "id": "NAMJNT4IYFE3N7FCYJWAKX3OKMQVIUSL7CN4EPBUXJNKSCTYCRHSVNTB"
        }
    },
    "service": {
        "address": "http://elastic-package-service-nats-1:8222/connz",
        "type": "nats"
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
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |
| nats.connection.idle_time | The period the connection is idle (sec) | long | counter |
| nats.connection.in.bytes | The amount of incoming bytes | long | counter |
| nats.connection.in.messages | The amount of incoming messages | long | counter |
| nats.connection.name | The name of the connection | keyword |  |
| nats.connection.out.bytes | The amount of outgoing bytes | long | counter |
| nats.connection.out.messages | The amount of outgoing messages | long | counter |
| nats.connection.pending_bytes | The number of pending bytes of this connection | long | gauge |
| nats.connection.subscriptions | The number of subscriptions in this connection | integer | gauge |
| nats.connection.uptime | The period the connection is up (sec) | long | counter |
| nats.server.id | The server ID | keyword |  |
| nats.server.time | Server time of metric creation | date |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |


### route

This is the `route` dataset of the Nats package, in charge of retrieving detailed
metric per route from a Nats instance.

An example event for `route` looks as following:

```json
{
    "@timestamp": "2022-01-12T02:49:43.071Z",
    "agent": {
        "ephemeral_id": "7603b971-4c23-4474-94d7-736540cccfbc",
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "nats.route",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "nats.route",
        "duration": 37120483,
        "ingested": "2022-01-12T02:49:47Z",
        "module": "nats"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "4ccba669f0df47fa3f57a9e4169ae7f1",
        "ip": [
            "172.18.0.4"
        ],
        "mac": [
            "02:42:ac:12:00:04"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "5.11.0-44-generic",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "metricset": {
        "name": "route",
        "period": 10000
    },
    "nats": {
        "route": {
            "in": {
                "bytes": 0,
                "messages": 0
            },
            "ip": "172.23.0.2",
            "out": {
                "bytes": 0,
                "messages": 0
            },
            "pending_size": 0,
            "port": 43132,
            "remote_id": "ND6TIOITFXLQL7IOQ6YF4YA76FO5DZKZ7RADTQFJH5Y22554RBAN23HE",
            "subscriptions": 0
        },
        "server": {
            "id": "NDLSAJ5QGWF5IZJSOSOC7P22NTXGFIQMULUEZR2VC4HT4STJU6L36AIB"
        }
    },
    "service": {
        "address": "http://elastic-package-service-nats-1:8222/routez",
        "type": "nats"
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
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |
| nats.route.in.bytes | The amount of incoming bytes | long | counter |
| nats.route.in.messages | The amount of incoming messages | long | counter |
| nats.route.ip | The ip of the route | ip |  |
| nats.route.out.bytes | The amount of outgoing bytes | long | counter |
| nats.route.out.messages | The amount of outgoing messages | long | counter |
| nats.route.pending_size | The number of pending routes | long | gauge |
| nats.route.port | The port of the route | integer |  |
| nats.route.remote_id | The remote id on which the route is connected to | keyword |  |
| nats.route.subscriptions | The number of subscriptions in this connection | integer | gauge |
| nats.server.id | The server ID | keyword |  |
| nats.server.time | Server time of metric creation | date |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |

