# ZooKeeper Integration

This integration periodically fetches logs and metrics from the [ZooKeeper](https://zookeeper.apache.org/) service.

## Compatibility

The ZooKeeper integration is tested with ZooKeeper 3.4.8 and is expected to work with all version >= 3.4.0. Versions prior to 3.4 do not support the mntr command.

## Logs

### Server Log

The `log` dataset reads and parses the ZooKeeper server logs.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2021-04-19T01:58:20.588-05:00",
    "agent": {
        "ephemeral_id": "5353d91d-20b0-470d-99e9-590628456a59",
        "hostname": "docker-fleet-agent",
        "id": "d2d8697c-368a-44a0-b52e-47be9b44c955",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.16.2"
    },
    "data_stream": {
        "dataset": "zookeeper.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.4.0"
    },
    "elastic_agent": {
        "id": "d2d8697c-368a-44a0-b52e-47be9b44c955",
        "snapshot": false,
        "version": "7.16.2"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "zookeeper.log",
        "ingested": "2021-12-23T23:56:11Z",
        "kind": "event",
        "original": "2021-04-19 01:58:20,588 [myid:] - INFO  [main:QuorumPeerConfig@117] - Reading configuration from: /app/zookeeper/bin/../conf/zoo.cfg",
        "timezone": "-05:00",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "7f9ea24f5509c98509297b0e8530fd71",
        "ip": [
            "192.168.224.7"
        ],
        "mac": [
            "02:42:c0:a8:e0:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "5.4.0-91-generic",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/test-log.log"
        },
        "level": "INFO",
        "logger": "QuorumPeerConfig",
        "offset": 133,
        "origin": {
            "file": {
                "line": 117
            }
        }
    },
    "message": "Reading configuration from: /app/zookeeper/bin/../conf/zoo.cfg",
    "process": {
        "thread": {
            "name": "main"
        }
    },
    "tags": [
        "preserve_original_event",
        "zookeeper-log"
    ]
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.logger | The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name. | keyword |
| log.offset | Log offset | long |
| log.origin.file.line | The line number of the file containing the source code which originated the log event. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.thread.name | Thread name. | keyword |
| service.node.name | Name of a service node. This allows for two nodes of the same service running on the same host to be differentiated. Therefore, `service.node.name` should typically be unique across nodes of a given service. In the case of Elasticsearch, the `service.node.name` could contain the unique node name within the Elasticsearch cluster. In cases where the service doesn't have the concept of a node name, the host name or container name can be used to distinguish running instances that make up this service. If those do not provide uniqueness (e.g. multiple instances of the service running on the same host) - the node name can be manually set. | keyword |
| tags | List of keywords used to tag each event. | keyword |


### Audit Logs

The `audit` dataset reads and parses the ZooKeeper audit logs.

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2021-04-19T01:58:20.588-05:00",
    "agent": {
        "ephemeral_id": "0c542b37-aa61-46bf-a903-12caba8daba4",
        "hostname": "docker-fleet-agent",
        "id": "d2d8697c-368a-44a0-b52e-47be9b44c955",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.16.2"
    },
    "data_stream": {
        "dataset": "zookeeper.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.4.0"
    },
    "elastic_agent": {
        "id": "d2d8697c-368a-44a0-b52e-47be9b44c955",
        "snapshot": false,
        "version": "7.16.2"
    },
    "event": {
        "action": "serverStart",
        "agent_id_status": "verified",
        "dataset": "zookeeper.audit",
        "ingested": "2021-12-23T23:55:09Z",
        "original": "2021-04-19 01:58:20,588 INFO audit.Log4jAuditLogger: user=zookeeper/192.168.1.3 operation=serverStart   result=success",
        "outcome": "success",
        "timezone": "-05:00"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "7f9ea24f5509c98509297b0e8530fd71",
        "ip": [
            "192.168.224.7"
        ],
        "mac": [
            "02:42:c0:a8:e0:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "5.4.0-91-generic",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/test-audit.log"
        },
        "level": "INFO",
        "logger": "audit.Log4jAuditLogger",
        "offset": 119
    },
    "related": {
        "user": [
            "zookeeper/192.168.1.3"
        ]
    },
    "tags": [
        "preserve_original_event",
        "zookeeper-log"
    ],
    "user": {
        "id": "zookeeper/192.168.1.3"
    },
    "zookeeper": {
        "audit": {
            "result": "success",
            "user": [
                "zookeeper/192.168.1.3"
            ]
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.address | Some event client addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.logger | The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name. | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.id | Unique identifier of the user. | keyword |
| zookeeper.audit.acl | String representation of znode ACL like cdrwa(create, delete,read, write, admin). This is logged only for setAcl operation | keyword |
| zookeeper.audit.result | Result of the operation. Possible values are (success/failure/invoked). Result "invoked" is used for serverStop operation because stop is logged before ensuring that server actually stopped. | keyword |
| zookeeper.audit.session | Client session id | keyword |
| zookeeper.audit.user | Comma separated list of users who are associate with a client session | keyword |
| zookeeper.audit.znode | Path of the znode | keyword |
| zookeeper.audit.znode_type | Type of znode in case of creation operation | keyword |


## Metrics

### connection

The `connection` dataset fetches the data returned by the `cons` admin keyword.

An example event for `connection` looks as following:

```json
{
    "@timestamp": "2020-07-06T16:12:07.612Z",
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
            "received": 1,
            "sent": 0,
            "interest_ops": 0,
            "queued": 0
        }
    },
    "client": {
        "ip": "172.28.0.1",
        "port": 44338
    },
    "event": {
        "dataset": "zookeeper.connection",
        "module": "zookeeper",
        "duration": 3093417
    },
    "agent": {
        "name": "zookeeper-01",
        "type": "metricbeat",
        "version": "8.0.0",
        "ephemeral_id": "4d221f8f-7147-4855-8ea3-b4d2a5b80ae0",
        "id": "2ff8a09c-c7f0-42f2-9fe1-65f7fd460651"
    },
    "ecs": {
        "version": "8.4.0"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| zookeeper.connection.interest_ops | Interest ops | long |
| zookeeper.connection.queued | Queued connections | long |
| zookeeper.connection.received | Received connections | long |
| zookeeper.connection.sent | Connections sent | long |


### mntr

The `mntr` Metricset fetches the data returned by the `mntr` admin keyword.

An example event for `mntr` looks as following:

```json
{
    "@timestamp": "2020-07-06T16:12:08.494Z",
    "zookeeper": {
        "mntr": {
            "open_file_descriptor_count": 49,
            "watch_count": 0,
            "server_state": "standalone",
            "max_file_descriptor_count": 1048576,
            "znode_count": 5,
            "outstanding_requests": 0,
            "ephemerals_count": 0,
            "packets": {
                "received": 152,
                "sent": 151
            },
            "num_alive_connections": 1,
            "approximate_data_size": 44,
            "latency": {
                "max": 0,
                "avg": 0,
                "min": 0
            }
        }
    },
    "ecs": {
        "version": "8.4.0"
    },
    "host": {
        "name": "zookeeper-01"
    },
    "agent": {
        "ephemeral_id": "4d221f8f-7147-4855-8ea3-b4d2a5b80ae0",
        "id": "2ff8a09c-c7f0-42f2-9fe1-65f7fd460651",
        "name": "zookeeper-01",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "service": {
        "version": "3.5.5-390fe37ea45dee01bf87dc1c042b5e3dcce88653, built on 05/03/2019 12:07 GMT",
        "address": "localhost:2181",
        "type": "zookeeper"
    },
    "event": {
        "duration": 15795652,
        "dataset": "zookeeper.mntr",
        "module": "zookeeper"
    },
    "metricset": {
        "name": "mntr",
        "period": 10000
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
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

```json
{
    "@timestamp": "2020-07-06T16:12:12.409Z",
    "event": {
        "module": "zookeeper",
        "duration": 3001938,
        "dataset": "zookeeper.server"
    },
    "metricset": {
        "name": "server",
        "period": 10000
    },
    "ecs": {
        "version": "8.4.0"
    },
    "host": {
        "name": "zookeeper-01"
    },
    "agent": {
        "name": "zookeeper-01",
        "type": "metricbeat",
        "version": "8.0.0",
        "ephemeral_id": "4d221f8f-7147-4855-8ea3-b4d2a5b80ae0",
        "id": "2ff8a09c-c7f0-42f2-9fe1-65f7fd460651"
    },
    "zookeeper": {
        "server": {
            "zxid": "0x0",
            "count": 0,
            "version_date": "2019-05-03T12:07:00Z",
            "received": 156,
            "mode": "standalone",
            "latency": {
                "avg": 0,
                "max": 0,
                "min": 0
            },
            "sent": 155,
            "epoch": 0,
            "node_count": 5,
            "connections": 1,
            "outstanding": 0
        }
    },
    "service": {
        "address": "localhost:2181",
        "type": "zookeeper",
        "version": "3.5.5-390fe37ea45dee01bf87dc1c042b5e3dcce88653"
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| service.version | Version of the service the data was collected from. This allows to look at a data set only for a specific version of a service. | keyword |
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

