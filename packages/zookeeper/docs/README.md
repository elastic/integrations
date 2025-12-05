# ZooKeeper Metrics Integration for Elastic

## Overview

The ZooKeeper Metrics integration for Elastic allows you to collect and monitor key performance metrics from Apache ZooKeeper, a centralized service for maintaining configuration information, naming, providing distributed synchronization, and providing group services. By ingesting ZooKeeper metrics into the Elastic Stack, you can gain deep insights into the health, performance, and stability of your distributed coordination service.

This integration facilitates:
- **Distributed Coordination**: Monitor the health of services used for managing configuration, leader election, and service discovery.
- **Performance Monitoring**: Track key metrics like latency, znode counts, and packet statistics to ensure optimal performance.
- **Resource Management**: Keep an eye on resource usage, including file descriptors and ephemeral nodes, to prevent outages.
- **Troubleshooting**: Quickly diagnose issues by correlating ZooKeeper metrics with other observability data in Elastic.

### Compatibility

This integration is tested with ZooKeeper 3.4.8 and is expected to work with all versions >= 3.4.0.

**Important**: Versions of ZooKeeper prior to 3.4 do not support the `mntr` command, which is required for collecting a significant portion of the metrics.

This integration is compatible with Elastic Stack version 8.13.0 or higher.

### How it works

The Elastic Agent connects to the ZooKeeper service and executes a set of administrative commands known as "Four-Letter Words" (`cons`, `mntr`, `srvr`) to gather metrics. The agent then sends this data to your Elastic deployment, where it is processed and visualized.

## What data does this integration collect?

This integration collects metrics from the ZooKeeper service. The collected data provides insights into server health, client connections, and overall performance.

The ZooKeeper Metrics integration collects the following data streams:
* **`connection`**: Gathers client connection information using the `cons` command, including IP addresses, ports, and packet statistics.
* **`mntr`**: Collects detailed server health and performance metrics via the `mntr` command, such as latency, znode counts, and watch counts.
* **`server`**: Fetches server status information using the `srvr` command, including the server's role (leader/follower), connection counts, and outstanding requests.

### Supported use cases

- **Monitor Distributed Systems**: Ensure the reliability of coordination services essential for distributed applications like Apache Kafka.
- **Proactive Alerting**: Set up alerts on critical metrics, such as high latency or low follower counts, to proactively address potential issues.
- **Capacity Planning**: Analyze trends in znode counts and connection numbers to plan for future scaling needs.

## What do I need to use this integration?

- A running ZooKeeper instance (version 3.4.0 or higher).
- The ZooKeeper client port (default: 2181) must be accessible from the host running the Elastic Agent.
- For ZooKeeper 3.6.0 and newer, the required four-letter word commands must be whitelisted.
- Elastic Stack version 8.13.0 or higher.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed on a host with network access to your ZooKeeper instance. For detailed installation instructions, refer to the Elastic Agent [installation guide](docs-content://reference/fleet/install-elastic-agents.md). Only one Elastic Agent is needed per host.

### Set up steps in ZooKeeper

For ZooKeeper versions 3.6.0 and above, you must explicitly enable the four-letter word commands required by this integration.

1.  **Enable four-letter word commands**:
    *   Open your ZooKeeper configuration file (typically `zoo.cfg`).
    *   Add or modify the following line to whitelist the required commands:
        ```
        4lw.commands.whitelist=mntr,cons,srvr
        ```
    *   Alternatively, you can use `4lw.commands.whitelist=*` to enable all four-letter word commands, but this is less secure.

2.  **Restart the ZooKeeper service**:
    *   After modifying the configuration, restart the ZooKeeper service for the changes to take effect.
    *   Use the appropriate command for your environment, such as `bin/zkServer.sh restart`.

3.  **Verify commands are enabled**:
    *   Test that the commands are accessible by running the following command from a machine with network access to ZooKeeper:
        ```sh
        echo mntr | nc localhost 2181
        ```
    *   You should receive a list of ZooKeeper metrics as a response.

### Set up steps in Kibana

1.  In Kibana, navigate to **Management > Integrations**.
2.  Search for "ZooKeeper Metrics" and select the integration.
3.  Click **Add ZooKeeper Metrics**.
4.  Configure the integration settings:
    *   **ZooKeeper address**: Enter the host and port of your ZooKeeper instance (e.g., `localhost:2181`).
    *   **Period**: Set how often to collect metrics (e.g., `10s`).
5.  Assign the integration to an agent policy.
6.  Click **Save and continue** to deploy the changes to your Elastic Agent.

### Validation

1.  **Verify ZooKeeper is accessible**:
    From the host running the Elastic Agent, test connectivity to ZooKeeper:
    ```sh
    echo mntr | nc <zookeeper-host> 2181
    ```
    You should receive metrics as output.

2.  **Check data ingestion in Kibana**:
    *   Navigate to **Discover** in Kibana.
    *   Select the ZooKeeper data streams (e.g., `metrics-zookeeper.mntr-*`).
    *   Verify that documents are being ingested with recent timestamps.

3.  **View dashboards**:
    *   Go to **Dashboards** in Kibana.
    *   Open the "[Metrics ZooKeeper] Overview" dashboard.
    *   Verify that visualizations are populated with data from your ZooKeeper service.

## Troubleshooting

### Common Configuration Issues

-   **No data collected**:
    *   Verify that the ZooKeeper service is running and accessible from the Elastic Agent host.
    *   Check that the ZooKeeper address and port in the integration configuration are correct.
    *   Ensure network connectivity between the Elastic Agent and ZooKeeper by using `telnet` or `nc`.
-   **Four-letter word commands not working**:
    *   For ZooKeeper 3.6.0 and newer, confirm that `4lw.commands.whitelist` is correctly configured in `zoo.cfg`.
    *   Restart the ZooKeeper service after modifying its configuration.
    *   Check ZooKeeper logs for any errors related to command whitelisting.

### Ingestion Errors

-   **Error message: "connection refused"**:
    *   Verify that ZooKeeper is listening on the configured address and port.
    *   Check firewall rules to ensure the port is accessible from the agent host.
-   **Error message: "mntr is not executed because it is not in the whitelist"**:
    *   Add `4lw.commands.whitelist=mntr,cons,srvr` to your `zoo.cfg` file and restart ZooKeeper.
-   **Missing or incomplete metrics**:
    *   Ensure your ZooKeeper version is 3.4.0 or higher. The `mntr` command is not available in earlier versions.

For additional help, refer to the official [ZooKeeper Troubleshooting Guide](https://zookeeper.apache.org/doc/current/zookeeperAdmin.html#sc_troubleshooting).

## Performance and Scaling

The ZooKeeper Metrics integration is designed to be lightweight and efficient. This section provides guidance on the performance impact of collecting and shipping metrics to Elastic.

*   **Collection Frequency and Data Volume**: The `period` setting in the integration policy determines how often metrics are collected. While the default of `10s` is suitable for most environments, a shorter collection interval will increase the volume of data sent to Elasticsearch and slightly increase the load on both the agent and the ZooKeeper server. Adjust this setting based on your monitoring and retention requirements.

*   **Scaling Data Collection**: For monitoring a large number of ZooKeeper nodes, you can deploy the Elastic Agent on each ZooKeeper host or on dedicated monitoring servers. Ensure that each agent has network connectivity to the respective ZooKeeper instance it is monitoring. For more information on architectures for scaling data collection, refer to the Elastic [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### connection

The `connection` data stream collects client connection information using ZooKeeper's `cons` command.

#### connection fields

To include a generated list of fields from the `fields/` directory, uncomment and use:
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


The event template function will be replace by a sample event, taken from `sample_event.json`, when building this integration.

To include a sample event from `sample_event.json`, uncomment and use:
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

### mntr

The `mntr` data stream collects detailed server health and performance metrics using ZooKeeper's `mntr` command.

#### mntr fields

To include a generated list of fields from the `fields/` directory, uncomment and use:
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


The event template function will be replace by a sample event, taken from `sample_event.json`, when building this integration.

To include a sample event from `sample_event.json`, uncomment and use:
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

### server

The `server` data stream collects server status information using ZooKeeper's `srvr` command.

#### server fields

To include a generated list of fields from the `fields/` directory, uncomment and use:
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


The event template function will be replace by a sample event, taken from `sample_event.json`, when building this integration.

To include a sample event from `sample_event.json`, uncomment and use:
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

### Inputs used

These inputs can be used with this integration:


### Vendor Resources

-   [Apache ZooKeeper Official Documentation](https://zookeeper.apache.org/doc/current/)
-   [Apache ZooKeeper Administrator's Guide](https://zookeeper.apache.org/doc/current/zookeeperAdmin.html)
-   [ZooKeeper Four Letter Words Commands](https://zookeeper.apache.org/doc/current/zookeeperAdmin.html#sc_4lw)
