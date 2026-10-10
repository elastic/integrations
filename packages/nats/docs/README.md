# NATS integration

This integration is used to collect logs and metrics from [NATS servers](https://nats.io/).
The integration collects metrics from [NATS monitoring server APIs](https://docs.nats.io/running-a-nats-service/nats_admin/monitoring).


## Compatibility

The NATS package is tested with NATS 2.10.27 and requires Elastic Agent 9.1+. The `jetstream` dataset requires NATS with JetStream enabled (NATS 2.2+), and consumer metrics require NATS 2.9+.

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
            "02-42-C0-A8-F5-07"
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

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

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

The default datasets are `stats`, `connections`, `routes` and `subscriptions` while `connection`, `route`
and `jetstream` datasets can be enabled to collect detailed metrics per connection/route and JetStream monitoring.

### stats

This is the `stats` dataset of the Nats package, in charge of retrieving generic
metrics from a Nats instance.


An example event for `stats` looks as following:

```json
{
    "@timestamp": "2024-06-18T06:49:17.492Z",
    "agent": {
        "ephemeral_id": "4b9c9086-97a0-4aec-9cc4-b227f25eaf7b",
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "nats.stats",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "nats.stats",
        "duration": 1739425,
        "ingested": "2024-06-18T06:49:29Z",
        "module": "nats"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.245.7"
        ],
        "mac": [
            "02-42-C0-A8-F5-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.102.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "stats",
        "period": 10000
    },
    "nats": {
        "server": {
            "id": "NDCZVPEIJLTFLUSYR6Y4OSKTDJ5QD4LTTBSOKJ6HPX3K3QZPF6CI6VMI",
            "time": "2024-06-18T06:49:17.492Z"
        },
        "stats": {
            "cores": 12,
            "cpu": 1.03,
            "http": {
                "req_stats": {
                    "uri": {
                        "connz": 0,
                        "root": 0,
                        "routez": 0,
                        "subsz": 0,
                        "varz": 1
                    }
                }
            },
            "in": {
                "bytes": 29849184,
                "messages": 1865574
            },
            "mem": {
                "bytes": 8806400
            },
            "out": {
                "bytes": 0,
                "messages": 0
            },
            "remotes": 1,
            "slow_consumers": 0,
            "total_connections": 1,
            "uptime": 13
        }
    },
    "service": {
        "address": "http://elastic-package-service-nats-1:8222/varz",
        "type": "nats"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

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
| nats.stats.http.req_stats.uri.gatewayz | The number of hits on gatewayz monitoring uri | long | counter |
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
| nats.stats.server_name | The name of the NATS server. | keyword |  |
| nats.stats.slow_consumers | The number of slow consumers currently on NATS | long | gauge |
| nats.stats.total_connections | The number of totally created clients | long | counter |
| nats.stats.uptime | The period the server is up (sec) | long | counter |
| nats.stats.version | The specifies version. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |


### connections

This is the `connections` dataset of the Nats package, in charge of retrieving generic
metrics about connections from a Nats instance.

An example event for `connections` looks as following:

```json
{
    "@timestamp": "2024-06-18T06:42:06.763Z",
    "agent": {
        "ephemeral_id": "dd10a7db-f158-4b9b-aaf2-af4cdc3d6b06",
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "nats.connections",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "nats.connections",
        "duration": 1514602,
        "ingested": "2024-06-18T06:42:18Z",
        "module": "nats"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.245.7"
        ],
        "mac": [
            "02-42-C0-A8-F5-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.102.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
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
            "id": "NCNKDXBFQLH5L4U6H3BPZX2CYTOLLFFFKKMAPUCSKE2QYMMS2S7HGYMN",
            "time": "2024-06-18T06:42:06.763Z"
        }
    },
    "service": {
        "address": "http://elastic-package-service-nats-1:8222/connz",
        "type": "nats"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

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
    "@timestamp": "2024-06-18T06:46:57.937Z",
    "agent": {
        "ephemeral_id": "109393c6-0e20-4b2a-b653-3fa5e35b5f7c",
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "nats.routes",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "nats.routes",
        "duration": 1390061,
        "ingested": "2024-06-18T06:47:09Z",
        "module": "nats"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.245.7"
        ],
        "mac": [
            "02-42-C0-A8-F5-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.102.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
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
            "id": "NCTCCFMHSIRDQEDRY54BNE6H5D2S476BITJEDHPZMOMCKZOITM6WWA6V",
            "time": "2024-06-18T06:46:57.937Z"
        }
    },
    "service": {
        "address": "http://elastic-package-service-nats-1:8222/routez",
        "type": "nats"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

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
    "@timestamp": "2024-06-18T06:51:43.719Z",
    "agent": {
        "ephemeral_id": "20d397d4-1143-4670-8a66-d8b8bceb57ac",
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "nats.subscriptions",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "nats.subscriptions",
        "duration": 1163583,
        "ingested": "2024-06-18T06:51:55Z",
        "module": "nats"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.245.7"
        ],
        "mac": [
            "02-42-C0-A8-F5-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.102.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
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

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

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
    "@timestamp": "2024-06-18T06:39:34.665Z",
    "agent": {
        "ephemeral_id": "3565b6dd-89b9-4d31-bc0e-52bd652289ee",
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "nats.connection",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "nats.connection",
        "duration": 1778759,
        "ingested": "2024-06-18T06:39:46Z",
        "module": "nats"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.245.7"
        ],
        "mac": [
            "02-42-C0-A8-F5-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.102.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
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
                "bytes": 31946336,
                "messages": 1996646
            },
            "name": "NATS Benchmark",
            "out": {
                "bytes": 0,
                "messages": 0
            },
            "pending_bytes": 0,
            "subscriptions": 0,
            "uptime": 14
        },
        "server": {
            "id": "NCKVGU7EX4KDOQDL6CQIEYBWSAVCA37KXRD5UOGRNGIFXOMDAV3VYKFJ"
        }
    },
    "service": {
        "address": "http://elastic-package-service-nats-1:8222/connz",
        "type": "nats"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

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
| nats.connection.id | A unique numeric identifier assigned by the NATS server to a connection | keyword |  |
| nats.connection.idle_time | The period the connection is idle (sec) | long | counter |
| nats.connection.in.bytes | The amount of incoming bytes | long | counter |
| nats.connection.in.messages | The amount of incoming messages | long | counter |
| nats.connection.ip | The ip of the connection | ip |  |
| nats.connection.kind | The kind of the connection (Client, Leafnode, etc.) | keyword |  |
| nats.connection.lang | Language of the file. | keyword |  |
| nats.connection.last_activity | The timestamp of the last activity on this connection | date |  |
| nats.connection.name | The name of the connection | keyword |  |
| nats.connection.out.bytes | The amount of outgoing bytes | long | counter |
| nats.connection.out.messages | The amount of outgoing messages | long | counter |
| nats.connection.pending_bytes | The number of pending bytes of this connection | long | gauge |
| nats.connection.port | The port of the connection | integer |  |
| nats.connection.start | The timestamp when the connection was established | date |  |
| nats.connection.subscriptions | The number of subscriptions in this connection | integer | gauge |
| nats.connection.type | The type of the connection | keyword |  |
| nats.connection.uptime | The period the connection is up (sec) | long | counter |
| nats.connection.version | The specifies version | keyword |  |
| nats.server.id | The server ID | keyword |  |
| nats.server.time | Server time of metric creation | date |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |


### jetstream

This is the `jetstream` dataset of the Nats package, in charge of retrieving
JetStream metrics from a NATS server. It collects data from the [/jsz](https://docs.nats.io/learn/monitoring/monitoring-endpoints#jsz-reports-jetstream-state) monitoring endpoint.

The `jetstream` dataset supports four categories of metrics that can be enabled independently:

* `stats` — General JetStream server stats (streams, consumers, messages, memory, storage).
* `account` — Per-account JetStream metrics (memory, storage, API stats).
* `stream` — Per-stream metrics (state, config, cluster info).
* `consumer` — Per-consumer metrics (delivered, ack floor, pending, config). Requires NATS 2.9+.

Account, stream, and consumer metrics can be filtered by name. Filters are cumulative and apply even if a category is not enabled but name filters are configured. When no names are configured, all entities are reported.

This dataset requires Elastic Agent 9.1+ and a NATS server with JetStream enabled.

An example event for `jetstream` looks as following:

```json
{
    "@timestamp": "2025-03-16T15:24:47.293Z",
    "agent": {
        "ephemeral_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "9.1.0"
    },
    "data_stream": {
        "dataset": "nats.jetstream",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "snapshot": false,
        "version": "9.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "nats.jetstream",
        "duration": 115000,
        "ingested": "2025-03-16T15:24:49Z",
        "module": "nats"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.245.7"
        ],
        "mac": [
            "02-42-C0-A8-F5-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.102.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "jetstream",
        "period": 10000
    },
    "nats": {
        "jetstream": {
            "category": "stats",
            "stats": {
                "accounts": 1,
                "bytes": 17395590,
                "config": {
                    "max_memory": 12427170816,
                    "max_storage": 752333079552,
                    "store_dir": "/tmp/nats/jetstream",
                    "sync_interval": 120000000000
                },
                "consumers": 0,
                "memory": 0,
                "messages": 102327,
                "reserved_memory": 0,
                "reserved_storage": 1073741824,
                "storage": 17395590,
                "streams": 1
            }
        },
        "server": {
            "id": "NBUWPVHICBBDHQZ3OPY2AEAVJVHDOQEVIQND3RLRUMCIZZEKHXHX5GDW",
            "time": "2025-03-16T15:24:47.293Z"
        }
    },
    "service": {
        "address": "http://elastic-package-service-nats-1:8222/jsz",
        "type": "nats"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

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
| nats.jetstream.account.accounts | The number of accounts using JetStream on the server. | long | gauge |
| nats.jetstream.account.api.errors | The total number of JetStream API errors encountered by this account. | long | counter |
| nats.jetstream.account.api.total | The total number of JetStream API calls made by this account. | long | counter |
| nats.jetstream.account.high_availability_assets | Indicates the number of JetStream high-availability (HA) assets allocated for an account. | integer | gauge |
| nats.jetstream.account.id | The ID of the JetStream account. | keyword |  |
| nats.jetstream.account.memory | The amount of memory in bytes currently used by JetStream for this account. | long | gauge |
| nats.jetstream.account.name | The name of the JetStream account. | keyword |  |
| nats.jetstream.account.reserved_memory | The maximum memory quota reserved for this account (in bytes). | long | gauge |
| nats.jetstream.account.reserved_storage | The maximum disk storage quota reserved for this account (in bytes). | long | gauge |
| nats.jetstream.account.storage | The amount of storage in bytes currently used by JetStream for this account. | long | gauge |
| nats.jetstream.category | The category of metrics represented in this event (stats, account, stream, or consumer). | keyword |  |
| nats.jetstream.consumer.account.id | The ID of the account. | keyword |  |
| nats.jetstream.consumer.account.name | The name of the account. | keyword |  |
| nats.jetstream.consumer.ack_floor.consumer_seq | The highest contiguous consumer sequence number that has been acknowledged. | long | gauge |
| nats.jetstream.consumer.ack_floor.last_active | The timestamp of the last acknowledged message. | date |  |
| nats.jetstream.consumer.ack_floor.stream_seq | The highest contiguous stream sequence number that has been acknowledged by the consumer. | long | gauge |
| nats.jetstream.consumer.cluster.leader | The ID of the leader in the cluster. | keyword |  |
| nats.jetstream.consumer.config.ack_policy | The configured ack policy for the consumer. | keyword |  |
| nats.jetstream.consumer.config.ack_wait | The duration (in nanoseconds) that the server will wait for an acknowledgment for any individual message once it has been delivered to a consumer. If an acknowledgment is not received in time, the message will be redelivered. | long | gauge |
| nats.jetstream.consumer.config.deliver_policy | The point in the stream from which to receive messages. | keyword |  |
| nats.jetstream.consumer.config.durable_name | The durable name of the consumer. If set, clients can have subscriptions bind to the consumer and resume until the consumer is explicitly deleted. | keyword |  |
| nats.jetstream.consumer.config.filter_subject | A subject that overlaps with the subjects bound to the stream to filter delivery to subscribers. | keyword |  |
| nats.jetstream.consumer.config.max_ack_pending | The maximum number of messages the consumer can have in-flight (delivered but unacknowledged) at any time. | long | gauge |
| nats.jetstream.consumer.config.max_deliver | The maximum number of times a message will be redelivered if not acknowledged. | long | gauge |
| nats.jetstream.consumer.config.max_waiting | The maximum number of pull requests a consumer can have waiting for messages. | long | gauge |
| nats.jetstream.consumer.config.name | The name of the consumer. | keyword |  |
| nats.jetstream.consumer.config.num_replicas | The number of replicas for the consumer's state in a JetStream cluster. | long | gauge |
| nats.jetstream.consumer.config.replay_policy | The configured replay policy for the consumer. | keyword |  |
| nats.jetstream.consumer.created | The date/time the consumer was created. | date |  |
| nats.jetstream.consumer.delivered.consumer_seq | The number of messages delivered to this consumer, starting from 1 when the consumer was created. | long | gauge |
| nats.jetstream.consumer.delivered.last_active | The timestamp of the last message delivered to the consumer. | date |  |
| nats.jetstream.consumer.delivered.stream_seq | The last stream sequence number of a message delivered to the consumer. Corresponds to the global sequence of messages in the stream. | long | gauge |
| nats.jetstream.consumer.last_active_time | Represents the last activity time of the consumer. | date |  |
| nats.jetstream.consumer.name | The name of the consumer. | keyword |  |
| nats.jetstream.consumer.num_ack_pending | The number of messages that have been delivered to the consumer but not yet acknowledged. | long | gauge |
| nats.jetstream.consumer.num_pending | The number of messages remaining in the stream that the consumer has not yet delivered to any client. | long | gauge |
| nats.jetstream.consumer.num_redelivered | The number of messages that had to be resent because they were previously delivered but not acknowledged within the Ack Wait time. | long | gauge |
| nats.jetstream.consumer.num_waiting | The number of pull requests currently waiting for messages to be delivered. | long | gauge |
| nats.jetstream.consumer.stream.name | The name of the stream. | keyword |  |
| nats.jetstream.stats.accounts | The total number of accounts on the JetStream server. | long | gauge |
| nats.jetstream.stats.bytes | The total number of message bytes on the JetStream server. | long | gauge |
| nats.jetstream.stats.config.max_memory | The maximum amount of memory (bytes) the JetStream server can use. | long | gauge |
| nats.jetstream.stats.config.max_storage | The maximum amount of storage (bytes) the JetStream server can use. | long | gauge |
| nats.jetstream.stats.config.store_dir | The path on disk where the JetStream storage lives. | keyword |  |
| nats.jetstream.stats.config.sync_interval | The fsync/sync interval for page cache in the filestore. | long | gauge |
| nats.jetstream.stats.consumers | The total number of consumers on the JetStream server. | long | gauge |
| nats.jetstream.stats.memory | The total amount of memory (bytes) used by the JetStream server. | long | gauge |
| nats.jetstream.stats.messages | The total number of messages on the JetStream server. | long | gauge |
| nats.jetstream.stats.reserved_memory | The amount of memory (bytes) reserved by the JetStream server. | long | gauge |
| nats.jetstream.stats.reserved_storage | The total amount of storage (bytes) reserved by the JetStream server. | long | gauge |
| nats.jetstream.stats.storage | The total amount of storage (bytes) used by the JetStream server. | long | gauge |
| nats.jetstream.stats.streams | The total number of streams on the JetStream server. | long | gauge |
| nats.jetstream.stream.account.id | The ID of the account. | keyword |  |
| nats.jetstream.stream.account.name | The name of the account. | keyword |  |
| nats.jetstream.stream.cluster.leader | The ID of the leader in the cluster. | keyword |  |
| nats.jetstream.stream.config.description | The description of the stream. | text |  |
| nats.jetstream.stream.config.max_age | Maximum age of any message in the stream, expressed in nanoseconds. | long | gauge |
| nats.jetstream.stream.config.max_bytes | Maximum number of bytes stored in the stream. Adheres to Discard Policy, removing oldest or refusing new messages if the Stream exceeds this size. | long | gauge |
| nats.jetstream.stream.config.max_consumers | The maximum number of consumers allowed for this stream. | long | gauge |
| nats.jetstream.stream.config.max_msg_size | The largest message (bytes) that will be accepted by the stream. The size of a message is a sum of payload and headers. | long | gauge |
| nats.jetstream.stream.config.max_msgs | Maximum number of messages stored in the stream. Adheres to Discard Policy, removing oldest or refusing new messages if the Stream exceeds this number of messages. | long | gauge |
| nats.jetstream.stream.config.max_msgs_per_subject | Limits maximum number of messages in the stream to retain per subject. | long | gauge |
| nats.jetstream.stream.config.num_replicas | How many replicas to keep for each message in a clustered JetStream. | long | gauge |
| nats.jetstream.stream.config.retention | The retention policy for the stream. | keyword |  |
| nats.jetstream.stream.config.storage | The storage type for stream data. | keyword |  |
| nats.jetstream.stream.config.subjects | The list of subjects bound to the stream. | keyword |  |
| nats.jetstream.stream.created | The date/time the stream was created. | date |  |
| nats.jetstream.stream.name | The name of the JetStream stream. | keyword |  |
| nats.jetstream.stream.state.bytes | The number of bytes of messages on the stream. | long | gauge |
| nats.jetstream.stream.state.consumer_count | The number of consumers on the stream. | long | gauge |
| nats.jetstream.stream.state.first_seq | The first sequence number on the stream. | long | gauge |
| nats.jetstream.stream.state.first_ts | The date/time corresponding to first_seq. | date |  |
| nats.jetstream.stream.state.last_seq | The last sequence number on the stream. | long | gauge |
| nats.jetstream.stream.state.last_ts | The date/time corresponding to last_seq. | date |  |
| nats.jetstream.stream.state.messages | The number of messages on the stream. | long | gauge |
| nats.jetstream.stream.state.num_deleted | The number of messages deleted from the stream. | long | gauge |
| nats.jetstream.stream.state.num_subjects | The number of subjects on the stream. | long | gauge |
| nats.server.id | The server ID | keyword |  |
| nats.server.time | Server time of metric creation | date |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |


### route

This is the `route` dataset of the Nats package, in charge of retrieving detailed
metric per route from a Nats instance.

An example event for `route` looks as following:

```json
{
    "@timestamp": "2024-06-18T06:44:35.066Z",
    "agent": {
        "ephemeral_id": "6003d8f1-6313-4eb7-8d62-101876d13951",
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "nats.route",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "97400795-188c-4140-a1ee-0002078c785d",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "nats.route",
        "duration": 1372502,
        "ingested": "2024-06-18T06:44:47Z",
        "module": "nats"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.245.7"
        ],
        "mac": [
            "02-42-C0-A8-F5-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.102.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
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
            "ip": "192.168.254.2",
            "out": {
                "bytes": 0,
                "messages": 0
            },
            "pending_size": 0,
            "port": 43212,
            "remote_id": "NDLBUBM32KU4PB6T3NDNQOFUCNPVHPGEVLS5K2CYY2RHGOV6M3UBBXCF",
            "subscriptions": 0
        },
        "server": {
            "id": "NADJLTRJXDJIDP4EJTJ2ZLIYQENQKIRX23VYDPNGHPAWEAHLESEEENNM"
        }
    },
    "service": {
        "address": "http://elastic-package-service-nats-1:8222/routez",
        "type": "nats"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

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

