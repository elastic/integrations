# STAN integration

This integration is used to collect logs and metrics from [STAN servers](https://github.com/nats-io/stan.go).
The integration collects metrics from [STAN monitoring server APIs](https://github.com/nats-io/nats-streaming-server/blob/master/server/monitor.go).


## Compatibility

The STAN package is tested with Stan 0.15.1.

## Logs

### log

The `log` dataset collects the STAN logs.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2022-01-12T04:11:35.529Z",
    "agent": {
        "ephemeral_id": "8d87b679-d308-4954-a88f-fdac22706bb7",
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "stan.log",
        "namespace": "ep",
        "type": "logs"
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
        "created": "2022-01-12T04:11:50.063Z",
        "dataset": "stan.log",
        "ingested": "2022-01-12T04:11:50Z",
        "kind": "event",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/stan.log"
        },
        "level": "info",
        "offset": 0
    },
    "message": "STREAM: Starting nats-streaming-server[test-cluster] version 0.15.1",
    "process": {
        "pid": 7
    },
    "stan": {
        "log": {
            "msg": {}
        }
    },
    "tags": [
        "forwarded",
        "stan-log"
    ]
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
| stan.log.client.id | The id of the client | integer |
| stan.log.msg.bytes | Size of the payload in bytes | long |
| stan.log.msg.error.message | Details about the error occurred | text |
| stan.log.msg.max_messages | An optional number of messages to wait for before automatically unsubscribing | integer |
| stan.log.msg.queue_group | The queue group which subscriber will join | text |
| stan.log.msg.reply_to | The inbox subject on which the publisher is listening for responses | keyword |
| stan.log.msg.sid | The unique alphanumeric subscription ID of the subject | integer |
| stan.log.msg.subject | Subject name this message was received on | keyword |
| stan.log.msg.type | The protocol message type | keyword |


## Metrics

The default datasets are `stats`, `channels`, and `subscriptions`.

### stats

This is the `stats` dataset of the STAN package, in charge of retrieving generic
metrics from a STAN instance.

An example event for `stats` looks as following:

```json
{
    "@timestamp": "2022-01-12T04:12:59.760Z",
    "agent": {
        "ephemeral_id": "6e4beb8a-ccda-438d-b3f4-e89b98e870d8",
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "stan.stats",
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
        "dataset": "stan.stats",
        "duration": 15794254,
        "ingested": "2022-01-12T04:13:00Z",
        "module": "stan"
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
        "period": 60000
    },
    "service": {
        "address": "http://elastic-package-service-stan-1:8222/streaming/serverz",
        "type": "stan"
    },
    "stan": {
        "cluster": {
            "id": "test-cluster"
        },
        "server": {
            "id": "JQCbrpPJGBxuQGsQ9Yx4Xs"
        },
        "stats": {
            "bytes": 0,
            "channels": 1,
            "clients": 100,
            "messages": 0,
            "state": "STANDALONE",
            "subscriptions": 100
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
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| stan.cluster.id | The cluster ID | keyword |  |
| stan.server.id | The server ID | keyword |  |
| stan.stats.bytes | Number of bytes consumed across all STAN queues | long | counter |
| stan.stats.channels | The number of STAN channels | integer | gauge |
| stan.stats.clients | The number of STAN clients | integer | gauge |
| stan.stats.messages | Number of messages across all STAN queues | long | counter |
| stan.stats.role | If clustered, role of this node in the cluster (Leader, Follower, Candidate) | keyword |  |
| stan.stats.state | The cluster / streaming configuration state (STANDALONE, CLUSTERED) | keyword |  |
| stan.stats.subscriptions | The number of STAN streaming subscriptions | integer | gauge |


### channels

This is the `channels` dataset of the STAN package, in charge of retrieving
metrics about channels from a STAN instance.

An example event for `channels` looks as following:

```json
{
    "@timestamp": "2022-01-12T04:11:05.571Z",
    "agent": {
        "ephemeral_id": "02c989d8-8cf2-4e65-bf07-a8e93785fdaa",
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "stan.channels",
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
        "dataset": "stan.channels",
        "duration": 22264899,
        "ingested": "2022-01-12T04:11:06Z",
        "module": "stan"
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
        "name": "channels",
        "period": 60000
    },
    "service": {
        "address": "http://elastic-package-service-stan-1:8222/streaming/channelsz?subs=1",
        "type": "stan"
    },
    "stan": {
        "channels": {
            "bytes": 0,
            "depth": 0,
            "first_seq": 0,
            "last_seq": 0,
            "messages": 0,
            "name": "foo"
        },
        "cluster": {
            "id": "test-cluster"
        },
        "server": {
            "id": "dEvzTKomxEioLU6oP1VuXM"
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
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| stan.channels.bytes | The number of STAN bytes in the channel | long | counter |
| stan.channels.depth | Queue depth based upon current sequence number and highest reported subscriber sequence number | long | gauge |
| stan.channels.first_seq | First sequence number stored in the channel. If first_seq \> min([seq in subscriptions]) data loss has possibly occurred | long |  |
| stan.channels.last_seq | Last sequence number stored in the channel | long | counter |
| stan.channels.messages | The number of STAN streaming messages | long | counter |
| stan.channels.name | The name of the STAN streaming channel | keyword |  |
| stan.cluster.id | The cluster ID | keyword |  |
| stan.server.id | The server ID | keyword |  |


### subscriptions

This is the `subscriptions` dataset of the STAN package, in charge of retrieving
metrics about subscriptions from a STAN instance.

An example event for `subscriptions` looks as following:

```json
{
    "@timestamp": "2022-01-12T04:13:52.133Z",
    "agent": {
        "ephemeral_id": "edb669a5-3b36-43d7-8190-d485d6517f69",
        "id": "9878d192-22ad-49b6-a6c2-9959b0815d04",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "stan.subscriptions",
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
        "dataset": "stan.subscriptions",
        "duration": 6243276,
        "ingested": "2022-01-12T04:13:53Z",
        "module": "stan"
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
        "period": 60000
    },
    "service": {
        "address": "http://elastic-package-service-stan-1:8222/streaming/channelsz?subs=1",
        "type": "stan"
    },
    "stan": {
        "cluster": {
            "id": "test-cluster"
        },
        "server": {
            "id": "NevWjtY7nB1yzea8TtJaGb"
        },
        "subscriptions": {
            "channel": "foo",
            "id": "benchmark-sub-25",
            "last_sent": 0,
            "offline": false,
            "pending": 0,
            "queue": "T",
            "stalled": false
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
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| stan.cluster.id | The cluster ID | keyword |  |
| stan.server.id | The server ID | keyword |  |
| stan.subscriptions.channel | The name of the STAN channel the subscription is associated with | keyword |  |
| stan.subscriptions.id | The name of the STAN channel subscription (client_id) | keyword |  |
| stan.subscriptions.last_sent | Last known sequence number of the subscription that was acked | long | counter |
| stan.subscriptions.offline | Is the subscriber marked as offline? | boolean |  |
| stan.subscriptions.pending | Number of pending messages from / to the subscriber | long | gauge |
| stan.subscriptions.queue | The name of the NATS queue that the STAN channel subscription is associated with, if any | keyword |  |
| stan.subscriptions.stalled | Is the subscriber known to be stalled? | boolean |  |
