# ZooKeeper Integration

This integration periodically fetches metrics from the [ZooKeeper](https://zookeeper.apache.org/) service.

## Compatibility

The ZooKeeper integration is tested with ZooKeeper 3.4.8 and is expected to work with all version >= 3.4.0. Versions prior to 3.4 do not support the mntr command.

## Metrics

### connection

The `connection` dataset fetches the data returned by the `cons` admin keyword.

An example event for `connection` looks as following:

```$json
{
  "_id": "5KTmJHMB--B0K1AVImYo",
  "_index": "metricbeat-8.0.0-2020.07.06-000001",
  "_score": null,
  "_source": {
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
      "version": "1.5.0"
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
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-07-06T16:12:07.612Z"
    ]
  }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| zookeeper.connection.interest_ops | Interest ops | long |
| zookeeper.connection.queued | Queued connections | long |
| zookeeper.connection.received | Received connections | long |
| zookeeper.connection.sent | Connections sent | long |


### mntr

The `mntr` Metricset fetches the data returned by the `mntr` admin keyword.

An example event for `mntr` looks as following:

```$json
{
  "_id": "5aTmJHMB--B0K1AVImYo",
  "_index": "metricbeat-8.0.0-2020.07.06-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-07-06T16:12:08.494Z",
    "agent": {
      "ephemeral_id": "4d221f8f-7147-4855-8ea3-b4d2a5b80ae0",
      "id": "2ff8a09c-c7f0-42f2-9fe1-65f7fd460651",
      "name": "zookeeper-01",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "ecs": {
      "version": "1.5.0"
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
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-07-06T16:12:08.494Z"
    ]
  }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.version | Version of the service the data was collected from. This allows to look at a data set only for a specific version of a service. | keyword |
| zookeeper.mntr.approximate_data_size | Approximate size of ZooKeeper data. | long |
| zookeeper.mntr.ephemerals_count | Number of ephemeral znodes. | long |
| zookeeper.mntr.followers | Number of followers seen by the current host. | long |
| zookeeper.mntr.hostname | ZooKeeper hostname. | keyword |
| zookeeper.mntr.latency.avg | Average latency between ensemble hosts in milliseconds. | long |
| zookeeper.mntr.latency.max | Maximum latency in milliseconds. | long |
| zookeeper.mntr.latency.min | Minimum latency in milliseconds. | long |
| zookeeper.mntr.max_file_descriptor_count | Maximum number of file descriptors allowed for the ZooKeeper process. | long |
| zookeeper.mntr.num_alive_connections | Number of connections to ZooKeeper that are currently alive. | long |
| zookeeper.mntr.open_file_descriptor_count | Number of file descriptors open by the ZooKeeper process. | long |
| zookeeper.mntr.outstanding_requests | Number of outstanding requests that need to be processed by the cluster. | long |
| zookeeper.mntr.packets.received | Number of ZooKeeper network packets received. | long |
| zookeeper.mntr.packets.sent | Number of ZooKeeper network packets sent. | long |
| zookeeper.mntr.pending_syncs | Number of pending syncs to carry out to ZooKeeper ensemble followers. | long |
| zookeeper.mntr.server_state | Role in the ZooKeeper ensemble. | keyword |
| zookeeper.mntr.synced_followers | Number of synced followers reported when a node server_state is leader. | long |
| zookeeper.mntr.watch_count | Number of watches currently set on the local ZooKeeper process. | long |
| zookeeper.mntr.znode_count | Number of znodes reported by the local ZooKeeper process. | long |


### server

The `server` Metricset fetches the data returned by the `srvr` admin keyword.

An example event for `server` looks as following:

```$json
{
  "_id": "QKTmJHMB--B0K1AVNGfq",
  "_index": "metricbeat-8.0.0-2020.07.06-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-07-06T16:12:12.409Z",
    "agent": {
      "ephemeral_id": "4d221f8f-7147-4855-8ea3-b4d2a5b80ae0",
      "id": "2ff8a09c-c7f0-42f2-9fe1-65f7fd460651",
      "name": "zookeeper-01",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "ecs": {
      "version": "1.5.0"
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
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-07-06T16:12:12.409Z"
    ],
    "zookeeper.server.version_date": [
      "2019-05-03T12:07:00.000Z"
    ]
  }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| zookeeper.server.connections | Number of clients currently connected to the server | long |
| zookeeper.server.count | Total transactions of the leader in epoch | long |
| zookeeper.server.epoch | Epoch value of the Zookeeper transaction ID. An epoch signifies the period in which a server is a leader | long |
| zookeeper.server.latency.avg | Average amount of time taken for the server to respond to a client request | long |
| zookeeper.server.latency.max | Maximum amount of time taken for the server to respond to a client request | long |
| zookeeper.server.latency.min | Minimum amount of time taken for the server to respond to a client request | long |
| zookeeper.server.mode | Mode of the server. In an ensemble, this may either be leader or follower. Otherwise, it is standalone | keyword |
| zookeeper.server.node_count | Total number of nodes | long |
| zookeeper.server.outstanding | Number of requests queued at the server. This exceeds zero when the server receives more requests than it is able to process | long |
| zookeeper.server.received | Number of requests received by the server | long |
| zookeeper.server.sent | Number of requests sent by the server | long |
| zookeeper.server.version_date | Date of the Zookeeper release currently in use | date |
| zookeeper.server.zxid | Unique value of the Zookeeper transaction ID. The zxid consists of an epoch and a counter. It is established by the leader and is used to determine the temporal ordering of changes | keyword |

