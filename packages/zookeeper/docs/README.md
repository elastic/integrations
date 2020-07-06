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
  "@timestamp": "2017-10-12T08:05:34.853Z",
  "client": {
    "ip": "172.17.0.1",
    "port": 47728
  },
  "event": {
    "dataset": "zookeeper.connection",
    "duration": 115000,
    "module": "zookeeper"
  },
  "metricset": {
    "name": "connection"
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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| zookeeper.connection.interest_ops | Interest ops | long |
| zookeeper.connection.queued | Queued connections | long |
| zookeeper.connection.received | Received connections | long |
| zookeeper.connection.sent | Connections sent | long |


### mntr

The `mntr` Metricset fetches the data returned by the `mntr` admin keyword.

An example event for `mntr` looks as following:

```$json
{
  "@timestamp": "2017-10-12T08:05:34.853Z",
  "event": {
    "dataset": "zookeeper.mntr",
    "duration": 115000,
    "module": "zookeeper"
  },
  "metricset": {
    "name": "mntr"
  },
  "service": {
    "address": "localhost:32770",
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
      "open_file_descriptor_count": 65,
      "outstanding_requests": 0,
      "packets": {
        "received": 2,
        "sent": 1
      },
      "server_state": "standalone",
      "watch_count": 0,
      "znode_count": 5
    }
  }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
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
  "@timestamp": "2017-10-12T08:05:34.853Z",
  "event": {
    "dataset": "zookeeper.server",
    "duration": 115000,
    "module": "zookeeper"
  },
  "metricset": {
    "name": "server"
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
      "received": 11,
      "sent": 10,
      "version_date": "2019-05-03T12:07:00Z",
      "zxid": "0x0"
    }
  }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
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

