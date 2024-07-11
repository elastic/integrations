# ZooKeeper Integration

This integration periodically fetches metrics from the [ZooKeeper](https://zookeeper.apache.org/) service.

## Compatibility

The ZooKeeper integration is tested with ZooKeeper 3.4.8 and is expected to work with all version >= 3.4.0. Versions prior to 3.4 do not support the mntr command.

## Metrics

### connection

The `connection` dataset fetches the data returned by the `cons` admin keyword.

An example event for `connection` looks as following:

```json
{
    "@timestamp": "2020-07-06T16:12:07.612Z",
    "agent": {
        "ephemeral_id": "4d221f8f-7147-4855-8ea3-b4d2a5b80ae0",
        "id": "2ff8a09c-c7f0-42f2-9fe1-65f7fd460651",
        "name": "zookeeper-01",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "client": {
        "ip": "172.28.0.1",
        "port": 44338
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "dataset": "zookeeper.connection",
        "duration": 3093417,
        "module": "zookeeper"
    },
    "host": {
        "name": "zookeeper-01"
    },
    "metricset": {
        "name": "connection",
        "period": 10000
    },
    "service": {
        "address": "localhost:2181",
        "type": "zookeeper"
    },
    "zookeeper": {
        "connection": {
            "interest_ops": 0,
            "queued": 0,
            "received": 1,
            "sent": 0
        }
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id |  | keyword |  |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |  |
| client.port | Port of the client. | long |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment.  Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.name | Name of the host.  It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| zookeeper.connection.interest_ops | Interest ops | long |  |
| zookeeper.connection.queued | Queued connections | long | gauge |
| zookeeper.connection.received | Received connections | long | counter |
| zookeeper.connection.sent | Connections sent | long | counter |


### mntr

The `mntr` Metricset fetches the data returned by the `mntr` admin keyword.

An example event for `mntr` looks as following:

```json
{
    "@timestamp": "2020-07-06T16:12:08.494Z",
    "agent": {
        "ephemeral_id": "4d221f8f-7147-4855-8ea3-b4d2a5b80ae0",
        "id": "2ff8a09c-c7f0-42f2-9fe1-65f7fd460651",
        "name": "zookeeper-01",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "dataset": "zookeeper.mntr",
        "duration": 15795652,
        "module": "zookeeper"
    },
    "host": {
        "name": "zookeeper-01"
    },
    "metricset": {
        "name": "mntr",
        "period": 10000
    },
    "service": {
        "address": "localhost:2181",
        "type": "zookeeper",
        "version": "3.5.5-390fe37ea45dee01bf87dc1c042b5e3dcce88653, built on 05/03/2019 12:07 GMT"
    },
    "zookeeper": {
        "mntr": {
            "approximate_data_size": 44,
            "ephemerals_count": 0,
            "latency": {
                "avg": 0,
                "max": 0,
                "min": 0
            },
            "max_file_descriptor_count": 1048576,
            "num_alive_connections": 1,
            "open_file_descriptor_count": 49,
            "outstanding_requests": 0,
            "packets": {
                "received": 152,
                "sent": 151
            },
            "server_state": "standalone",
            "watch_count": 0,
            "znode_count": 5
        }
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id |  | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment.  Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.name | Name of the host.  It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| zookeeper.mntr.approximate_data_size | Approximate size of ZooKeeper data. | long | gauge |
| zookeeper.mntr.ephemerals_count | Number of ephemeral znodes. | long | gauge |
| zookeeper.mntr.followers | Number of followers seen by the current host. | long | gauge |
| zookeeper.mntr.hostname | ZooKeeper hostname. | keyword |  |
| zookeeper.mntr.latency.avg | Average latency between ensemble hosts in milliseconds. | long | gauge |
| zookeeper.mntr.latency.max | Maximum latency in milliseconds. | long | gauge |
| zookeeper.mntr.latency.min | Minimum latency in milliseconds. | long | gauge |
| zookeeper.mntr.max_file_descriptor_count | Maximum number of file descriptors allowed for the ZooKeeper process. | long | gauge |
| zookeeper.mntr.num_alive_connections | Number of connections to ZooKeeper that are currently alive. | long | gauge |
| zookeeper.mntr.open_file_descriptor_count | Number of file descriptors open by the ZooKeeper process. | long | gauge |
| zookeeper.mntr.outstanding_requests | Number of outstanding requests that need to be processed by the cluster. | long | gauge |
| zookeeper.mntr.packets.received | Number of ZooKeeper network packets received. | long | gauge |
| zookeeper.mntr.packets.sent | Number of ZooKeeper network packets sent. | long | gauge |
| zookeeper.mntr.pending_syncs | Number of pending syncs to carry out to ZooKeeper ensemble followers. | long | gauge |
| zookeeper.mntr.server_state | Role in the ZooKeeper ensemble. | keyword |  |
| zookeeper.mntr.synced_followers | Number of synced followers reported when a node server_state is leader. | long | gauge |
| zookeeper.mntr.watch_count | Number of watches currently set on the local ZooKeeper process. | long | gauge |
| zookeeper.mntr.znode_count | Number of znodes reported by the local ZooKeeper process. | long | gauge |


### server

The `server` Metricset fetches the data returned by the `srvr` admin keyword.

An example event for `server` looks as following:

```json
{
    "@timestamp": "2020-07-06T16:12:12.409Z",
    "agent": {
        "ephemeral_id": "4d221f8f-7147-4855-8ea3-b4d2a5b80ae0",
        "id": "2ff8a09c-c7f0-42f2-9fe1-65f7fd460651",
        "name": "zookeeper-01",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "dataset": "zookeeper.server",
        "duration": 3001938,
        "module": "zookeeper"
    },
    "host": {
        "name": "zookeeper-01"
    },
    "metricset": {
        "name": "server",
        "period": 10000
    },
    "service": {
        "address": "localhost:2181",
        "type": "zookeeper",
        "version": "3.5.5-390fe37ea45dee01bf87dc1c042b5e3dcce88653"
    },
    "zookeeper": {
        "server": {
            "connections": 1,
            "count": 0,
            "epoch": 0,
            "latency": {
                "avg": 0,
                "max": 0,
                "min": 0
            },
            "mode": "standalone",
            "node_count": 5,
            "outstanding": 0,
            "received": 156,
            "sent": 155,
            "version_date": "2019-05-03T12:07:00Z",
            "zxid": "0x0"
        }
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id |  | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment.  Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.name | Name of the host.  It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| zookeeper.server.connections | Number of clients currently connected to the server | long | gauge |
| zookeeper.server.count | Total transactions of the leader in epoch | long | counter |
| zookeeper.server.epoch | Epoch value of the Zookeeper transaction ID. An epoch signifies the period in which a server is a leader | long |  |
| zookeeper.server.latency.avg | Average amount of time taken for the server to respond to a client request | long | gauge |
| zookeeper.server.latency.max | Maximum amount of time taken for the server to respond to a client request | long | gauge |
| zookeeper.server.latency.min | Minimum amount of time taken for the server to respond to a client request | long | gauge |
| zookeeper.server.mode | Mode of the server. In an ensemble, this may either be leader or follower. Otherwise, it is standalone | keyword |  |
| zookeeper.server.node_count | Total number of nodes | long | gauge |
| zookeeper.server.outstanding | Number of requests queued at the server. This exceeds zero when the server receives more requests than it is able to process | long | gauge |
| zookeeper.server.received | Number of requests received by the server | long | counter |
| zookeeper.server.sent | Number of requests sent by the server | long | counter |
| zookeeper.server.version_date | Date of the Zookeeper release currently in use | date |  |
| zookeeper.server.zxid | Unique value of the Zookeeper transaction ID. The zxid consists of an epoch and a counter. It is established by the leader and is used to determine the temporal ordering of changes | keyword |  |

