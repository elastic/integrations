# MongoDB Integration

This integration is used to fetch logs and metrics from [MongoDB](https://www.mongodb.com/).

## Compatibility

The `log` dataset is tested with logs from versions v3.2.11 and v4.4.4 in
plaintext and json formats.
The `collstats`, `dbstats`, `metrics`, `replstatus` and `status` datasets are 
tested with MongoDB 3.4 and 3.0 and are expected to work with all versions >= 2.8.

## MongoDB Privileges
In order to use the metrics datasets, the MongoDB user specified in the package
configuration needs to have certain [privileges](https://docs.mongodb.com/manual/core/authorization/#privileges).

We recommend using the [clusterMonitor](https://docs.mongodb.com/manual/reference/built-in-roles/#clusterMonitor) 
role to cover all the necessary privileges.

You can use the following command in Mongo shell to create the privileged user
(make sure you are using the `admin` db by using `db` command in Mongo shell).

```
db.createUser(
    {
        user: "beats",
        pwd: "pass",
        roles: ["clusterMonitor"]
    }
)
```

You can use the following command in Mongo shell to grant the role to an 
existing user (make sure you are using the `admin` db by using `db` command in 
Mongo shell).

```
db.grantRolesToUser("user", ["clusterMonitor"])
```

## Logs

### log

The `log` dataset collects the MongoDB logs.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2022-09-30T05:45:04.513Z",
    "agent": {
        "ephemeral_id": "d79631d7-f47d-4305-84e0-966867772449",
        "hostname": "docker-fleet-agent",
        "id": "d0af73b1-68c5-4a9b-900e-b1ab4bfc4f08",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.14.0"
    },
    "data_stream": {
        "dataset": "mongodb.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "1.10.0"
    },
    "elastic_agent": {
        "id": "d0af73b1-68c5-4a9b-900e-b1ab4bfc4f08",
        "snapshot": false,
        "version": "7.14.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "created": "2022-09-30T05:45:19.328Z",
        "dataset": "mongodb.log",
        "ingested": "2022-09-30T05:45:22.874882467Z",
        "kind": "event",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "2347a1bd8a3945949da8ab5c29f60774",
        "ip": [
            "172.19.0.7"
        ],
        "mac": [
            "02:42:ac:13:00:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "AltArch",
            "family": "redhat",
            "kernel": "5.10.124-linuxkit",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (AltArch)"
        }
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/mongodb.log"
        },
        "level": "I",
        "offset": 0
    },
    "message": "***** SERVER RESTARTED *****",
    "mongodb": {
        "log": {
            "component": "CONTROL",
            "context": "main"
        }
    },
    "tags": [
        "mongodb-logs"
    ]
}
```

The fields reported are:

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
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
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
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.flags | This field contains the flags of the event. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| mongodb.log.attr | Attributes related to the log message. | flattened |
| mongodb.log.component | Functional categorization of message | keyword |
| mongodb.log.context | Context of message | keyword |
| mongodb.log.id | Integer representing the unique identifier of the log statement | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |


## Metrics

### collstats

The `collstats` dataset uses the top administrative command to return usage 
statistics for each collection. It provides the amount of time, in microseconds,
used and a count of operations for the following types: total, readLock, writeLock,
queries, getmore, insert, update, remove, and commands.

It requires the following privileges, which is covered by the [clusterMonitor](https://docs.mongodb.com/manual/reference/built-in-roles/#clusterMonitor) role:

* [top action](https://docs.mongodb.com/manual/reference/privilege-actions/#top) on [cluster resource](https://docs.mongodb.com/manual/reference/resource-document/#cluster-resource)

An example event for `collstats` looks as following:

```json
{
    "@timestamp": "2022-09-30T05:43:41.148Z",
    "agent": {
        "ephemeral_id": "004e7564-1a48-40eb-8099-b51ddbd903dc",
        "hostname": "docker-fleet-agent",
        "id": "d0af73b1-68c5-4a9b-900e-b1ab4bfc4f08",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "7.14.0"
    },
    "data_stream": {
        "dataset": "mongodb.collstats",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "1.10.0"
    },
    "elastic_agent": {
        "id": "d0af73b1-68c5-4a9b-900e-b1ab4bfc4f08",
        "snapshot": false,
        "version": "7.14.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "mongodb.collstats",
        "duration": 2032209,
        "ingested": "2022-09-30T05:43:44.696723467Z",
        "module": "mongodb"
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "2347a1bd8a3945949da8ab5c29f60774",
        "ip": [
            "172.19.0.7"
        ],
        "mac": [
            "02:42:ac:13:00:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "AltArch",
            "family": "redhat",
            "kernel": "5.10.124-linuxkit",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (AltArch)"
        }
    },
    "metricset": {
        "name": "collstats",
        "period": 10000
    },
    "mongodb": {
        "collstats": {
            "collection": "oplog.rs",
            "commands": {
                "count": 0,
                "time": {
                    "us": 0
                }
            },
            "db": "local",
            "getmore": {
                "count": 0,
                "time": {
                    "us": 0
                }
            },
            "insert": {
                "count": 0,
                "time": {
                    "us": 0
                }
            },
            "lock": {
                "read": {
                    "count": 16,
                    "time": {
                        "us": 121
                    }
                },
                "write": {
                    "count": 0,
                    "time": {
                        "us": 0
                    }
                }
            },
            "name": "local.oplog.rs",
            "queries": {
                "count": 0,
                "time": {
                    "us": 0
                }
            },
            "remove": {
                "count": 0,
                "time": {
                    "us": 0
                }
            },
            "total": {
                "count": 16,
                "time": {
                    "us": 121
                }
            },
            "update": {
                "count": 0,
                "time": {
                    "us": 0
                }
            }
        }
    },
    "service": {
        "address": "mongodb://elastic-package-service-mongodb-1",
        "type": "mongodb"
    }
}
```

The fields reported are:

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
| mongodb.collstats.collection | Collection name. | keyword |
| mongodb.collstats.commands.count | Number of database commands executed. | long |
| mongodb.collstats.commands.time.us | Time executing database commands in microseconds. | long |
| mongodb.collstats.db | Database name. | keyword |
| mongodb.collstats.getmore.count | Number of times a cursor asked for more data. | long |
| mongodb.collstats.getmore.time.us | Time asking for more cursor rows in microseconds. | long |
| mongodb.collstats.insert.count | Number of document insert events. | long |
| mongodb.collstats.insert.time.us | Time inserting new documents in microseconds. | long |
| mongodb.collstats.lock.read.count | Number of read lock wait events. | long |
| mongodb.collstats.lock.read.time.us | Time waiting for read locks in microseconds. | long |
| mongodb.collstats.lock.write.count | Number of write lock wait events. | long |
| mongodb.collstats.lock.write.time.us | Time waiting for write locks in microseconds. | long |
| mongodb.collstats.name | Combination of database and collection name. | keyword |
| mongodb.collstats.queries.count | Number of queries executed. | long |
| mongodb.collstats.queries.time.us | Time running queries in microseconds. | long |
| mongodb.collstats.remove.count | Number of document delete events. | long |
| mongodb.collstats.remove.time.us | Time deleting documents in microseconds. | long |
| mongodb.collstats.total.count | Total number of lock wait events. | long |
| mongodb.collstats.total.time.us | Total waiting time for locks in microseconds. | long |
| mongodb.collstats.update.count | Number of document update events. | long |
| mongodb.collstats.update.time.us | Time updating documents in microseconds. | long |
| service.address | Address of the machine where the service is running. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


### dbstats

The `dbstats` dataset collects storage statistics for a given database. 

It requires the following privileges, which is covered by the [clusterMonitor](https://docs.mongodb.com/manual/reference/built-in-roles/#clusterMonitor) role:

* [listDatabases](https://docs.mongodb.com/manual/reference/privilege-actions/#listDatabases) 
action on [cluster resource](https://docs.mongodb.com/manual/reference/resource-document/#cluster-resource)

* for each of the databases, also need [dbStats](https://docs.mongodb.com/manual/reference/privilege-actions/#dbStats)
action on the [database resource](https://docs.mongodb.com/manual/reference/resource-document/#database-and-or-collection-resource)

An example event for `dbstats` looks as following:

```json
{
    "@timestamp": "2022-09-30T05:44:25.115Z",
    "agent": {
        "ephemeral_id": "b94c8fab-16af-4c9c-8f7f-a52c16f70dae",
        "hostname": "docker-fleet-agent",
        "id": "d0af73b1-68c5-4a9b-900e-b1ab4bfc4f08",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "7.14.0"
    },
    "data_stream": {
        "dataset": "mongodb.dbstats",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "1.10.0"
    },
    "elastic_agent": {
        "id": "d0af73b1-68c5-4a9b-900e-b1ab4bfc4f08",
        "snapshot": false,
        "version": "7.14.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "mongodb.dbstats",
        "duration": 2733125,
        "ingested": "2022-09-30T05:44:28.693023626Z",
        "module": "mongodb"
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "2347a1bd8a3945949da8ab5c29f60774",
        "ip": [
            "172.19.0.7"
        ],
        "mac": [
            "02:42:ac:13:00:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "AltArch",
            "family": "redhat",
            "kernel": "5.10.124-linuxkit",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (AltArch)"
        }
    },
    "metricset": {
        "name": "dbstats",
        "period": 10000
    },
    "mongodb": {
        "dbstats": {
            "avg_obj_size": {
                "bytes": 522
            },
            "collections": 3,
            "data_size": {
                "bytes": 1566
            },
            "db": "local",
            "file_size": {},
            "index_size": {
                "bytes": 12288
            },
            "indexes": 3,
            "ns_size_mb": {},
            "num_extents": 0,
            "objects": 3,
            "storage_size": {
                "bytes": 12288
            }
        }
    },
    "service": {
        "address": "mongodb://elastic-package-service-mongodb-1",
        "type": "mongodb"
    }
}
```

The fields reported are:

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
| mongodb.dbstats.avg_obj_size.bytes |  | long |
| mongodb.dbstats.collections |  | integer |
| mongodb.dbstats.data_file_version.major |  | long |
| mongodb.dbstats.data_file_version.minor |  | long |
| mongodb.dbstats.data_size.bytes |  | long |
| mongodb.dbstats.db |  | keyword |
| mongodb.dbstats.extent_free_list.num |  | long |
| mongodb.dbstats.extent_free_list.size.bytes |  | long |
| mongodb.dbstats.file_size.bytes |  | long |
| mongodb.dbstats.index_size.bytes |  | long |
| mongodb.dbstats.indexes |  | long |
| mongodb.dbstats.ns_size_mb.mb |  | long |
| mongodb.dbstats.num_extents |  | long |
| mongodb.dbstats.objects |  | long |
| mongodb.dbstats.storage_size.bytes |  | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


### metrics

It requires the following privileges, which is covered by the clusterMonitor role:

* [serverStatus](https://docs.mongodb.com/manual/reference/privilege-actions/#serverStatus) 
action on [cluster resource](https://docs.mongodb.com/manual/reference/resource-document/#cluster-resource)

An example event for `metrics` looks as following:

```json
{
    "@timestamp": "2022-09-30T05:46:05.475Z",
    "agent": {
        "ephemeral_id": "a80c2528-263a-4e2a-b44c-f4f9df75c7a5",
        "hostname": "docker-fleet-agent",
        "id": "d0af73b1-68c5-4a9b-900e-b1ab4bfc4f08",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "7.14.0"
    },
    "data_stream": {
        "dataset": "mongodb.metrics",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "1.10.0"
    },
    "elastic_agent": {
        "id": "d0af73b1-68c5-4a9b-900e-b1ab4bfc4f08",
        "snapshot": false,
        "version": "7.14.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "mongodb.metrics",
        "duration": 3150375,
        "ingested": "2022-09-30T05:46:09.023273503Z",
        "module": "mongodb"
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "2347a1bd8a3945949da8ab5c29f60774",
        "ip": [
            "172.19.0.7"
        ],
        "mac": [
            "02:42:ac:13:00:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "AltArch",
            "family": "redhat",
            "kernel": "5.10.124-linuxkit",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (AltArch)"
        }
    },
    "metricset": {
        "name": "metrics",
        "period": 10000
    },
    "mongodb": {
        "metrics": {
            "commands": {
                "aggregate": {
                    "failed": 0,
                    "total": 0
                },
                "build_info": {
                    "failed": 0,
                    "total": 28
                },
                "coll_stats": {
                    "failed": 0,
                    "total": 0
                },
                "connection_pool_stats": {
                    "failed": 0,
                    "total": 0
                },
                "count": {
                    "failed": 0,
                    "total": 0
                },
                "db_stats": {
                    "failed": 0,
                    "total": 0
                },
                "distinct": {
                    "failed": 0,
                    "total": 0
                },
                "find": {
                    "failed": 0,
                    "total": 0
                },
                "get_cmd_line_opts": {
                    "failed": 0,
                    "total": 0
                },
                "get_last_error": {
                    "failed": 0,
                    "total": 0
                },
                "get_log": {
                    "failed": 0,
                    "total": 0
                },
                "get_more": {
                    "failed": 0,
                    "total": 0
                },
                "get_parameter": {
                    "failed": 0,
                    "total": 0
                },
                "host_info": {
                    "failed": 0,
                    "total": 0
                },
                "insert": {
                    "failed": 0,
                    "total": 0
                },
                "is_master": {
                    "failed": 0,
                    "total": 44
                },
                "is_self": {
                    "failed": 0,
                    "total": 0
                },
                "last_collections": {
                    "failed": 0,
                    "total": 0
                },
                "last_commands": {
                    "failed": 0,
                    "total": 0
                },
                "list_databased": {
                    "failed": 0,
                    "total": 0
                },
                "list_indexes": {
                    "failed": 0,
                    "total": 0
                },
                "ping": {
                    "failed": 0,
                    "total": 2
                },
                "profile": {
                    "failed": 0,
                    "total": 0
                },
                "replset_get_rbid": {
                    "failed": 0,
                    "total": 0
                },
                "replset_get_status": {
                    "failed": 14,
                    "total": 14
                },
                "replset_heartbeat": {
                    "failed": 0,
                    "total": 0
                },
                "replset_update_position": {
                    "failed": 0,
                    "total": 0
                },
                "server_status": {
                    "failed": 0,
                    "total": 16
                },
                "update": {
                    "failed": 0,
                    "total": 0
                },
                "whatsmyuri": {
                    "failed": 0,
                    "total": 14
                }
            },
            "cursor": {
                "open": {
                    "no_timeout": 0,
                    "pinned": 0,
                    "total": 0
                },
                "timed_out": 0
            },
            "document": {
                "deleted": 0,
                "inserted": 0,
                "returned": 0,
                "updated": 0
            },
            "get_last_error": {
                "write_timeouts": 0,
                "write_wait": {
                    "count": 0,
                    "ms": 0
                }
            },
            "operation": {
                "scan_and_order": 0,
                "write_conflicts": 0
            },
            "query_executor": {
                "scanned_documents": {
                    "count": 0
                },
                "scanned_indexes": {
                    "count": 0
                }
            },
            "replication": {
                "apply": {
                    "attempts_to_become_secondary": 0,
                    "batches": {
                        "count": 0,
                        "time": {
                            "ms": 0
                        }
                    },
                    "ops": 0
                },
                "buffer": {
                    "count": 0,
                    "max_size": {
                        "bytes": 0
                    },
                    "size": {
                        "bytes": 0
                    }
                },
                "executor": {
                    "counters": {
                        "cancels": 0,
                        "event_created": 0,
                        "event_wait": 0,
                        "scheduled": {
                            "dbwork": 0,
                            "exclusive": 0,
                            "failures": 0,
                            "netcmd": 0,
                            "work": 0,
                            "work_at": 0
                        },
                        "waits": 0
                    },
                    "event_waiters": 0,
                    "network_interface": "\nNetworkInterfaceASIO Operations' Diagnostic:\nOperation:    Count:   \nConnecting    0        \nIn Progress   0        \nSucceeded     0        \nCanceled      0        \nFailed        0        \nTimed Out     0        \n\n",
                    "queues": {
                        "free": 0,
                        "in_progress": {
                            "dbwork": 0,
                            "exclusive": 0,
                            "network": 0
                        },
                        "ready": 0,
                        "sleepers": 0
                    },
                    "shutting_down": false,
                    "unsignaled_events": 0
                },
                "initial_sync": {
                    "completed": 0,
                    "failed_attempts": 0,
                    "failures": 0
                },
                "network": {
                    "bytes": 0,
                    "getmores": {
                        "count": 0,
                        "time": {
                            "ms": 0
                        }
                    },
                    "ops": 0,
                    "reders_created": 0
                },
                "preload": {
                    "docs": {
                        "count": 0,
                        "time": {
                            "ms": 0
                        }
                    },
                    "indexes": {
                        "count": 0,
                        "time": {
                            "ms": 0
                        }
                    }
                }
            },
            "storage": {
                "search": {
                    "bucket_exhausted": 0,
                    "requests": 0,
                    "scanned": 0
                }
            },
            "ttl": {
                "deleted_documents": {
                    "count": 0
                },
                "passes": {
                    "count": 0
                }
            }
        }
    },
    "service": {
        "address": "mongodb://elastic-package-service-mongodb-1",
        "type": "mongodb"
    }
}
```

The fields reported are:

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
| mongodb.metrics.commands.aggregate.failed |  | long |
| mongodb.metrics.commands.aggregate.total |  | long |
| mongodb.metrics.commands.build_info.failed |  | long |
| mongodb.metrics.commands.build_info.total |  | long |
| mongodb.metrics.commands.coll_stats.failed |  | long |
| mongodb.metrics.commands.coll_stats.total |  | long |
| mongodb.metrics.commands.connection_pool_stats.failed |  | long |
| mongodb.metrics.commands.connection_pool_stats.total |  | long |
| mongodb.metrics.commands.count.failed |  | long |
| mongodb.metrics.commands.count.total |  | long |
| mongodb.metrics.commands.db_stats.failed |  | long |
| mongodb.metrics.commands.db_stats.total |  | long |
| mongodb.metrics.commands.distinct.failed |  | long |
| mongodb.metrics.commands.distinct.total |  | long |
| mongodb.metrics.commands.find.failed |  | long |
| mongodb.metrics.commands.find.total |  | long |
| mongodb.metrics.commands.get_cmd_line_opts.failed |  | long |
| mongodb.metrics.commands.get_cmd_line_opts.total |  | long |
| mongodb.metrics.commands.get_last_error.failed |  | long |
| mongodb.metrics.commands.get_last_error.total |  | long |
| mongodb.metrics.commands.get_log.failed |  | long |
| mongodb.metrics.commands.get_log.total |  | long |
| mongodb.metrics.commands.get_more.failed |  | long |
| mongodb.metrics.commands.get_more.total |  | long |
| mongodb.metrics.commands.get_parameter.failed |  | long |
| mongodb.metrics.commands.get_parameter.total |  | long |
| mongodb.metrics.commands.host_info.failed |  | long |
| mongodb.metrics.commands.host_info.total |  | long |
| mongodb.metrics.commands.insert.failed |  | long |
| mongodb.metrics.commands.insert.total |  | long |
| mongodb.metrics.commands.is_master.failed |  | long |
| mongodb.metrics.commands.is_master.total |  | long |
| mongodb.metrics.commands.is_self.failed |  | long |
| mongodb.metrics.commands.is_self.total |  | long |
| mongodb.metrics.commands.last_collections.failed |  | long |
| mongodb.metrics.commands.last_collections.total |  | long |
| mongodb.metrics.commands.last_commands.failed |  | long |
| mongodb.metrics.commands.last_commands.total |  | long |
| mongodb.metrics.commands.list_databased.failed |  | long |
| mongodb.metrics.commands.list_databased.total |  | long |
| mongodb.metrics.commands.list_indexes.failed |  | long |
| mongodb.metrics.commands.list_indexes.total |  | long |
| mongodb.metrics.commands.ping.failed |  | long |
| mongodb.metrics.commands.ping.total |  | long |
| mongodb.metrics.commands.profile.failed |  | long |
| mongodb.metrics.commands.profile.total |  | long |
| mongodb.metrics.commands.replset_get_rbid.failed |  | long |
| mongodb.metrics.commands.replset_get_rbid.total |  | long |
| mongodb.metrics.commands.replset_get_status.failed |  | long |
| mongodb.metrics.commands.replset_get_status.total |  | long |
| mongodb.metrics.commands.replset_heartbeat.failed |  | long |
| mongodb.metrics.commands.replset_heartbeat.total |  | long |
| mongodb.metrics.commands.replset_update_position.failed |  | long |
| mongodb.metrics.commands.replset_update_position.total |  | long |
| mongodb.metrics.commands.server_status.failed |  | long |
| mongodb.metrics.commands.server_status.total |  | long |
| mongodb.metrics.commands.update.failed |  | long |
| mongodb.metrics.commands.update.total |  | long |
| mongodb.metrics.commands.whatsmyuri.failed |  | long |
| mongodb.metrics.commands.whatsmyuri.total |  | long |
| mongodb.metrics.cursor.open.no_timeout | The number of open cursors with the option DBQuery.Option.noTimeout set to prevent timeout. | long |
| mongodb.metrics.cursor.open.pinned | The number of `pinned` open cursors. | long |
| mongodb.metrics.cursor.open.total | The number of cursors that MongoDB is maintaining for clients. | long |
| mongodb.metrics.cursor.timed_out | The total number of cursors that have timed out since the server process started. | long |
| mongodb.metrics.document.deleted | The total number of documents deleted. | long |
| mongodb.metrics.document.inserted | The total number of documents inserted. | long |
| mongodb.metrics.document.returned | The total number of documents returned by queries. | long |
| mongodb.metrics.document.updated | The total number of documents updated. | long |
| mongodb.metrics.get_last_error.write_timeouts | The number of times that write concern operations have timed out as a result of the wtimeout threshold to getLastError. | long |
| mongodb.metrics.get_last_error.write_wait.count | The total number of getLastError operations with a specified write concern (i.e. w) greater than 1. | long |
| mongodb.metrics.get_last_error.write_wait.ms | The total amount of time in milliseconds that the mongod has spent performing getLastError operations with write concern (i.e. w) greater than 1. | long |
| mongodb.metrics.operation.scan_and_order | The total number of queries that return sorted numbers that cannot perform the sort operation using an index. | long |
| mongodb.metrics.operation.write_conflicts | The total number of queries that encountered write conflicts. | long |
| mongodb.metrics.query_executor.scanned_documents.count | The total number of documents scanned during queries and query-plan evaluation. | long |
| mongodb.metrics.query_executor.scanned_indexes.count | The total number of index items scanned during queries and query-plan evaluation. | long |
| mongodb.metrics.replication.apply.attempts_to_become_secondary |  | long |
| mongodb.metrics.replication.apply.batches.count | The total number of batches applied across all databases. | long |
| mongodb.metrics.replication.apply.batches.time.ms | The total amount of time in milliseconds the mongod has spent applying operations from the oplog. | long |
| mongodb.metrics.replication.apply.ops | The total number of oplog operations applied. | long |
| mongodb.metrics.replication.buffer.count | The current number of operations in the oplog buffer. | long |
| mongodb.metrics.replication.buffer.max_size.bytes | The maximum size of the buffer. This value is a constant setting in the mongod, and is not configurable. | long |
| mongodb.metrics.replication.buffer.size.bytes | The current size of the contents of the oplog buffer. | long |
| mongodb.metrics.replication.executor.counters.cancels |  | long |
| mongodb.metrics.replication.executor.counters.event_created |  | long |
| mongodb.metrics.replication.executor.counters.event_wait |  | long |
| mongodb.metrics.replication.executor.counters.scheduled.dbwork |  | long |
| mongodb.metrics.replication.executor.counters.scheduled.exclusive |  | long |
| mongodb.metrics.replication.executor.counters.scheduled.failures |  | long |
| mongodb.metrics.replication.executor.counters.scheduled.netcmd |  | long |
| mongodb.metrics.replication.executor.counters.scheduled.work |  | long |
| mongodb.metrics.replication.executor.counters.scheduled.work_at |  | long |
| mongodb.metrics.replication.executor.counters.waits |  | long |
| mongodb.metrics.replication.executor.event_waiters |  | long |
| mongodb.metrics.replication.executor.network_interface |  | keyword |
| mongodb.metrics.replication.executor.queues.free |  | long |
| mongodb.metrics.replication.executor.queues.in_progress.dbwork |  | long |
| mongodb.metrics.replication.executor.queues.in_progress.exclusive |  | long |
| mongodb.metrics.replication.executor.queues.in_progress.network |  | long |
| mongodb.metrics.replication.executor.queues.ready |  | long |
| mongodb.metrics.replication.executor.queues.sleepers |  | long |
| mongodb.metrics.replication.executor.shutting_down |  | boolean |
| mongodb.metrics.replication.executor.unsignaled_events |  | long |
| mongodb.metrics.replication.initial_sync.completed |  | long |
| mongodb.metrics.replication.initial_sync.failed_attempts |  | long |
| mongodb.metrics.replication.initial_sync.failures |  | long |
| mongodb.metrics.replication.network.bytes | The total amount of data read from the replication sync source. | long |
| mongodb.metrics.replication.network.getmores.count | The total number of getmore operations | long |
| mongodb.metrics.replication.network.getmores.time.ms | The total amount of time required to collect data from getmore operations. | long |
| mongodb.metrics.replication.network.ops | The total number of operations read from the replication source. | long |
| mongodb.metrics.replication.network.reders_created | The total number of oplog query processes created. | long |
| mongodb.metrics.replication.preload.docs.count | The total number of documents loaded during the pre-fetch stage of replication. | long |
| mongodb.metrics.replication.preload.docs.time.ms |  | long |
| mongodb.metrics.replication.preload.indexes.count | The total number of index entries loaded by members before updating documents as part of the pre-fetch stage of replication. | long |
| mongodb.metrics.replication.preload.indexes.time.ms | The total amount of time, in milliseconds, spent loading index entries as part of the pre-fetch stage of replication. | long |
| mongodb.metrics.storage.search.bucket_exhausted | The number of times that mongod has checked the free list without finding a suitably large record allocation. | long |
| mongodb.metrics.storage.search.requests | The number of times mongod has searched for available record allocations. | long |
| mongodb.metrics.storage.search.scanned | The number of available record allocations mongod has searched. | long |
| mongodb.metrics.ttl.deleted_documents.count | The total number of documents deleted from collections with a ttl index. | long |
| mongodb.metrics.ttl.passes.count | The number of times the background process removes documents from collections with a ttl index. | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


### replstatus
The `replstatus` dataset collects status of the replica set.
It requires the following privileges, which is covered by the [clusterMonitor](https://docs.mongodb.com/manual/reference/built-in-roles/#clusterMonitor) role:

* [find/listCollections](https://docs.mongodb.com/manual/reference/privilege-actions/#find) action on the [local database](https://docs.mongodb.com/manual/reference/local-database/) resource
* [collStats](https://docs.mongodb.com/manual/reference/privilege-actions/#collStats) action on the [local.oplog.rs](https://docs.mongodb.com/manual/reference/local-database/#local.oplog.rs) collection resource
* [replSetGetStatus](https://docs.mongodb.com/manual/reference/privilege-actions/#replSetGetStatus) action on [cluster resource](https://docs.mongodb.com/manual/reference/resource-document/#cluster-resource)

An example event for `replstatus` looks as following:

```json
{
    "@timestamp": "2022-09-21T14:39:38.568Z",
    "agent": {
        "ephemeral_id": "83e49bca-2845-4919-b064-e235fe36d0ff",
        "id": "5912bcc1-2372-4d61-b9db-29a677c0278f",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.4.0"
    },
    "data_stream": {
        "dataset": "mongodb.replstatus",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "5912bcc1-2372-4d61-b9db-29a677c0278f",
        "snapshot": false,
        "version": "8.4.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "mongodb.replstatus",
        "duration": 9661958671,
        "ingested": "2022-09-21T14:40:02Z",
        "module": "mongodb"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "5016511f0829451ea244f458eebf2212",
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
            "kernel": "5.10.124-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "replstatus",
        "period": 10000
    },
    "mongodb": {
        "replstatus": {
            "headroom": {},
            "lag": {},
            "members": {
                "arbiter": {
                    "count": 0,
                    "hosts": []
                },
                "down": {
                    "count": 0,
                    "hosts": []
                },
                "primary": {
                    "host": "127.0.0.1:27017",
                    "optime": 1663771187
                },
                "recovering": {
                    "count": 0,
                    "hosts": []
                },
                "rollback": {
                    "count": 0,
                    "hosts": []
                },
                "secondary": {
                    "count": 0,
                    "hosts": [],
                    "optimes": []
                },
                "startup2": {
                    "count": 0,
                    "hosts": []
                },
                "unhealthy": {
                    "count": 0,
                    "hosts": []
                },
                "unknown": {
                    "count": 0,
                    "hosts": []
                }
            },
            "oplog": {
                "first": {
                    "timestamp": 1663771125
                },
                "last": {
                    "timestamp": 1663771125
                },
                "size": {
                    "allocated": 2036425728,
                    "used": 4510
                },
                "window": 0
            },
            "optimes": {
                "applied": 1663771187,
                "durable": 1663771187,
                "last_committed": 1663771187
            },
            "server_date": "2022-09-21T14:39:48.226Z",
            "set_name": "beats"
        }
    },
    "service": {
        "address": "mongodb://elastic-package-service-mongodb-1",
        "type": "mongodb"
    }
}
```

The fields reported are:

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
| mongodb.replstatus.headroom.max | Difference between primary's oplog window and the replication lag of the fastest secondary | long |
| mongodb.replstatus.headroom.min | Difference between primary's oplog window and the replication lag of the slowest secondary | long |
| mongodb.replstatus.lag.max | Difference between optime of primary and slowest secondary | long |
| mongodb.replstatus.lag.min | Difference between optime of primary and fastest secondary | long |
| mongodb.replstatus.members.arbiter.count | Count of arbiters | long |
| mongodb.replstatus.members.arbiter.hosts | List of arbiters hosts | keyword |
| mongodb.replstatus.members.down.count | Count of `down` members | long |
| mongodb.replstatus.members.down.hosts | List of `down` members hosts | keyword |
| mongodb.replstatus.members.primary.host | Host address of the primary | keyword |
| mongodb.replstatus.members.primary.optime | Optime of primary | keyword |
| mongodb.replstatus.members.recovering.count | Count of members in the `recovering` state | long |
| mongodb.replstatus.members.recovering.hosts | List of recovering members hosts | keyword |
| mongodb.replstatus.members.rollback.count | Count of members in the `rollback` state | long |
| mongodb.replstatus.members.rollback.hosts | List of members in the `rollback` state | keyword |
| mongodb.replstatus.members.secondary.count |  | long |
| mongodb.replstatus.members.secondary.hosts | List of secondary hosts | keyword |
| mongodb.replstatus.members.secondary.optimes | Optimes of secondaries | keyword |
| mongodb.replstatus.members.startup2.count | Count of members in the `startup2` state | long |
| mongodb.replstatus.members.startup2.hosts | List of initializing members hosts | keyword |
| mongodb.replstatus.members.unhealthy.count | Count of unhealthy members | long |
| mongodb.replstatus.members.unhealthy.hosts | List of members' hosts with healthy = false | keyword |
| mongodb.replstatus.members.unknown.count | Count of members with `unknown` state | long |
| mongodb.replstatus.members.unknown.hosts | List of members' hosts in the `unknown` state | keyword |
| mongodb.replstatus.oplog.first.timestamp | Timestamp of the first (i.e. earliest) operation in the replstatus | long |
| mongodb.replstatus.oplog.last.timestamp | Timestamp of the last (i.e. latest) operation in the replstatus | long |
| mongodb.replstatus.oplog.size.allocated | The total amount of space used by the replstatus in bytes. | long |
| mongodb.replstatus.oplog.size.used | total amount of space allocated to the replstatus in bytes. | long |
| mongodb.replstatus.oplog.window | The difference between the first and last operation in the replstatus. | long |
| mongodb.replstatus.optimes.applied | Information, from the viewpoint of this member, regarding the most recent operation that has been applied to this member of the replica set. | long |
| mongodb.replstatus.optimes.durable | Information, from the viewpoint of this member, regarding the most recent operation that has been written to the journal of this member of the replica set. | long |
| mongodb.replstatus.optimes.last_committed | Information, from the viewpoint of this member, regarding the most recent operation that has been written to a majority of replica set members. | long |
| mongodb.replstatus.server_date | Reflects the current time according to the server that processed the replSetGetStatus command. | date |
| mongodb.replstatus.set_name | The name of the replica set. | keyword |
| service.address | Address of the machine where the service is running. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


### status

It requires the following privileges, which is covered by the [clusterMonitor](https://docs.mongodb.com/manual/reference/built-in-roles/#clusterMonitor) role:

* [serverStatus](https://docs.mongodb.com/manual/reference/privilege-actions/#serverStatus) 
action on [cluster resource](https://docs.mongodb.com/manual/reference/resource-document/#cluster-resource)

An example event for `status` looks as following:

```json
{
    "@timestamp": "2022-09-30T05:46:56.312Z",
    "agent": {
        "ephemeral_id": "dfcb0d66-6463-4416-a92c-ba2412e615de",
        "hostname": "docker-fleet-agent",
        "id": "d0af73b1-68c5-4a9b-900e-b1ab4bfc4f08",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "7.14.0"
    },
    "data_stream": {
        "dataset": "mongodb.status",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "1.10.0"
    },
    "elastic_agent": {
        "id": "d0af73b1-68c5-4a9b-900e-b1ab4bfc4f08",
        "snapshot": false,
        "version": "7.14.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "mongodb.status",
        "duration": 3136250,
        "ingested": "2022-09-30T05:46:59.865043763Z",
        "module": "mongodb"
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "2347a1bd8a3945949da8ab5c29f60774",
        "ip": [
            "172.19.0.7"
        ],
        "mac": [
            "02:42:ac:13:00:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "AltArch",
            "family": "redhat",
            "kernel": "5.10.124-linuxkit",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (AltArch)"
        }
    },
    "metricset": {
        "name": "status",
        "period": 10000
    },
    "mongodb": {
        "status": {
            "asserts": {
                "msg": 0,
                "regular": 0,
                "rollovers": 0,
                "user": 0,
                "warning": 0
            },
            "connections": {
                "available": 838859,
                "current": 1,
                "total_created": 16
            },
            "extra_info": {
                "heap_usage": {},
                "page_faults": 0
            },
            "global_lock": {
                "active_clients": {
                    "readers": 0,
                    "total": 8,
                    "writers": 0
                },
                "current_queue": {
                    "readers": 0,
                    "total": 0,
                    "writers": 0
                },
                "total_time": {
                    "us": 15257000
                }
            },
            "local_time": "2022-09-30T05:46:56.315Z",
            "locks": {
                "collection": {
                    "acquire": {
                        "count": {
                            "W": 1,
                            "r": 20
                        }
                    },
                    "deadlock": {},
                    "wait": {}
                },
                "database": {
                    "acquire": {
                        "count": {
                            "R": 1,
                            "W": 8,
                            "r": 35
                        }
                    },
                    "deadlock": {},
                    "wait": {}
                },
                "global": {
                    "acquire": {
                        "count": {
                            "W": 2,
                            "r": 112,
                            "w": 8
                        }
                    },
                    "deadlock": {},
                    "wait": {}
                },
                "meta_data": {
                    "acquire": {
                        "count": {
                            "w": 1
                        }
                    },
                    "deadlock": {},
                    "wait": {}
                },
                "oplog": {
                    "acquire": {
                        "count": {
                            "r": 15
                        }
                    },
                    "deadlock": {},
                    "wait": {}
                }
            },
            "memory": {
                "bits": 64,
                "mapped": {
                    "mb": 0
                },
                "mapped_with_journal": {
                    "mb": 0
                },
                "resident": {
                    "mb": 62
                },
                "virtual": {
                    "mb": 952
                }
            },
            "network": {
                "in": {
                    "bytes": 11076
                },
                "out": {
                    "bytes": 407574
                },
                "requests": 239
            },
            "ops": {
                "counters": {
                    "command": 120,
                    "delete": 0,
                    "getmore": 0,
                    "insert": 0,
                    "query": 1,
                    "update": 0
                },
                "latencies": {
                    "commands": {
                        "count": 119,
                        "latency": 5782
                    },
                    "reads": {
                        "count": 0,
                        "latency": 0
                    },
                    "writes": {
                        "count": 0,
                        "latency": 0
                    }
                },
                "replicated": {
                    "command": 0,
                    "delete": 0,
                    "getmore": 0,
                    "insert": 0,
                    "query": 0,
                    "update": 0
                }
            },
            "storage_engine": {
                "name": "wiredTiger"
            },
            "uptime": {
                "ms": 15258
            },
            "wired_tiger": {
                "cache": {
                    "dirty": {
                        "bytes": 21104
                    },
                    "maximum": {
                        "bytes": 3578789888
                    },
                    "pages": {
                        "evicted": 0,
                        "read": 0,
                        "write": 0
                    },
                    "used": {
                        "bytes": 22756
                    }
                },
                "concurrent_transactions": {
                    "read": {
                        "available": 128,
                        "out": 0,
                        "total_tickets": 128
                    },
                    "write": {
                        "available": 128,
                        "out": 0,
                        "total_tickets": 128
                    }
                },
                "log": {
                    "flushes": 152,
                    "max_file_size": {
                        "bytes": 104857600
                    },
                    "scans": 0,
                    "size": {
                        "bytes": 33554432
                    },
                    "syncs": 12,
                    "write": {
                        "bytes": 14336
                    },
                    "writes": 40
                }
            }
        }
    },
    "process": {
        "name": "mongod"
    },
    "service": {
        "address": "mongodb://elastic-package-service-mongodb-1",
        "type": "mongodb",
        "version": "3.4.24"
    }
}
```

The fields reported are:

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
| mongodb.status.asserts.msg | Number of msg assertions produced by the server. | long |
| mongodb.status.asserts.regular | Number of regular assertions produced by the server. | long |
| mongodb.status.asserts.rollovers | Number of rollovers assertions produced by the server. | long |
| mongodb.status.asserts.user | Number of user assertions produced by the server. | long |
| mongodb.status.asserts.warning | Number of warning assertions produced by the server. | long |
| mongodb.status.background_flushing.average.ms | The average time spent flushing to disk per flush event. | long |
| mongodb.status.background_flushing.flushes | A counter that collects the number of times the database has flushed all writes to disk. | long |
| mongodb.status.background_flushing.last.ms | The amount of time, in milliseconds, that the last flush operation took to complete. | long |
| mongodb.status.background_flushing.last_finished | A timestamp of the last completed flush operation. | date |
| mongodb.status.background_flushing.total.ms | The total number of milliseconds (ms) that the mongod processes have spent writing (i.e. flushing) data to disk. Because this is an absolute value, consider the value of `flushes` and `average_ms` to provide better context for this datum. | long |
| mongodb.status.connections.available | The number of unused available incoming connections the database can provide. | long |
| mongodb.status.connections.current | The number of connections to the database server from clients. This number includes the current shell session. Consider the value of `available` to add more context to this datum. | long |
| mongodb.status.connections.total_created | A count of all incoming connections created to the server. This number includes connections that have since closed. | long |
| mongodb.status.extra_info.heap_usage.bytes | The total size in bytes of heap space used by the database process. Only available on Unix/Linux. | long |
| mongodb.status.extra_info.page_faults | The total number of page faults that require disk operations. Page faults refer to operations that require the database server to access data that isn't available in active memory. | long |
| mongodb.status.global_lock.active_clients.readers | The number of the active client connections performing read operations. | long |
| mongodb.status.global_lock.active_clients.total | Total number of the active client connections performing read or write operations. | long |
| mongodb.status.global_lock.active_clients.writers | The number of the active client connections performing write operations. | long |
| mongodb.status.global_lock.current_queue.readers | The number of operations that are currently queued and waiting for the read lock. | long |
| mongodb.status.global_lock.current_queue.total | The total number of operations queued waiting for the lock (i.e., the sum of current_queue.readers and current_queue.writers). | long |
| mongodb.status.global_lock.current_queue.writers | The number of operations that are currently queued and waiting for the write lock. | long |
| mongodb.status.global_lock.total_time.us | The time, in microseconds, since the database last started and created the globalLock. This is roughly equivalent to total server uptime. | long |
| mongodb.status.journaling.commits | The number of transactions written to the journal during the last journal group commit interval. | long |
| mongodb.status.journaling.commits_in_write_lock | Count of the commits that occurred while a write lock was held. Commits in a write lock indicate a MongoDB node under a heavy write load and call for further diagnosis. | long |
| mongodb.status.journaling.compression | The compression ratio of the data written to the journal. | long |
| mongodb.status.journaling.early_commits | The number of times MongoDB requested a commit before the scheduled journal group commit interval. | long |
| mongodb.status.journaling.journaled.mb | The amount of data in megabytes (MB) written to journal during the last journal group commit interval. | long |
| mongodb.status.journaling.times.commits.ms | The amount of time spent for commits. | long |
| mongodb.status.journaling.times.commits_in_write_lock.ms | The amount of time spent for commits that occurred while a write lock was held. | long |
| mongodb.status.journaling.times.dt.ms | The amount of time over which MongoDB collected the times data. Use this field to provide context to the other times field values. | long |
| mongodb.status.journaling.times.prep_log_buffer.ms | The amount of time spent preparing to write to the journal. Smaller values indicate better journal performance. | long |
| mongodb.status.journaling.times.remap_private_view.ms | The amount of time spent remapping copy-on-write memory mapped views. Smaller values indicate better journal performance. | long |
| mongodb.status.journaling.times.write_to_data_files.ms | The amount of time spent writing to data files after journaling. File system speeds and device interfaces can affect performance. | long |
| mongodb.status.journaling.times.write_to_journal.ms | The amount of time spent actually writing to the journal. File system speeds and device interfaces can affect performance. | long |
| mongodb.status.journaling.write_to_data_files.mb | The amount of data in megabytes (MB) written from journal to the data files during the last journal group commit interval. | long |
| mongodb.status.local_time | Local time as reported by the MongoDB instance. | date |
| mongodb.status.locks.collection.acquire.count.R |  | long |
| mongodb.status.locks.collection.acquire.count.W |  | long |
| mongodb.status.locks.collection.acquire.count.r |  | long |
| mongodb.status.locks.collection.acquire.count.w |  | long |
| mongodb.status.locks.collection.deadlock.count.R |  | long |
| mongodb.status.locks.collection.deadlock.count.W |  | long |
| mongodb.status.locks.collection.deadlock.count.r |  | long |
| mongodb.status.locks.collection.deadlock.count.w |  | long |
| mongodb.status.locks.collection.wait.count.R |  | long |
| mongodb.status.locks.collection.wait.count.W |  | long |
| mongodb.status.locks.collection.wait.count.r |  | long |
| mongodb.status.locks.collection.wait.count.w |  | long |
| mongodb.status.locks.collection.wait.us.R |  | long |
| mongodb.status.locks.collection.wait.us.W |  | long |
| mongodb.status.locks.collection.wait.us.r |  | long |
| mongodb.status.locks.collection.wait.us.w |  | long |
| mongodb.status.locks.database.acquire.count.R |  | long |
| mongodb.status.locks.database.acquire.count.W |  | long |
| mongodb.status.locks.database.acquire.count.r |  | long |
| mongodb.status.locks.database.acquire.count.w |  | long |
| mongodb.status.locks.database.deadlock.count.R |  | long |
| mongodb.status.locks.database.deadlock.count.W |  | long |
| mongodb.status.locks.database.deadlock.count.r |  | long |
| mongodb.status.locks.database.deadlock.count.w |  | long |
| mongodb.status.locks.database.wait.count.R |  | long |
| mongodb.status.locks.database.wait.count.W |  | long |
| mongodb.status.locks.database.wait.count.r |  | long |
| mongodb.status.locks.database.wait.count.w |  | long |
| mongodb.status.locks.database.wait.us.R |  | long |
| mongodb.status.locks.database.wait.us.W |  | long |
| mongodb.status.locks.database.wait.us.r |  | long |
| mongodb.status.locks.database.wait.us.w |  | long |
| mongodb.status.locks.global.acquire.count.R |  | long |
| mongodb.status.locks.global.acquire.count.W |  | long |
| mongodb.status.locks.global.acquire.count.r |  | long |
| mongodb.status.locks.global.acquire.count.w |  | long |
| mongodb.status.locks.global.deadlock.count.R |  | long |
| mongodb.status.locks.global.deadlock.count.W |  | long |
| mongodb.status.locks.global.deadlock.count.r |  | long |
| mongodb.status.locks.global.deadlock.count.w |  | long |
| mongodb.status.locks.global.wait.count.R |  | long |
| mongodb.status.locks.global.wait.count.W |  | long |
| mongodb.status.locks.global.wait.count.r |  | long |
| mongodb.status.locks.global.wait.count.w |  | long |
| mongodb.status.locks.global.wait.us.R |  | long |
| mongodb.status.locks.global.wait.us.W |  | long |
| mongodb.status.locks.global.wait.us.r |  | long |
| mongodb.status.locks.global.wait.us.w |  | long |
| mongodb.status.locks.meta_data.acquire.count.R |  | long |
| mongodb.status.locks.meta_data.acquire.count.W |  | long |
| mongodb.status.locks.meta_data.acquire.count.r |  | long |
| mongodb.status.locks.meta_data.acquire.count.w |  | long |
| mongodb.status.locks.meta_data.deadlock.count.R |  | long |
| mongodb.status.locks.meta_data.deadlock.count.W |  | long |
| mongodb.status.locks.meta_data.deadlock.count.r |  | long |
| mongodb.status.locks.meta_data.deadlock.count.w |  | long |
| mongodb.status.locks.meta_data.wait.count.R |  | long |
| mongodb.status.locks.meta_data.wait.count.W |  | long |
| mongodb.status.locks.meta_data.wait.count.r |  | long |
| mongodb.status.locks.meta_data.wait.count.w |  | long |
| mongodb.status.locks.meta_data.wait.us.R |  | long |
| mongodb.status.locks.meta_data.wait.us.W |  | long |
| mongodb.status.locks.meta_data.wait.us.r |  | long |
| mongodb.status.locks.meta_data.wait.us.w |  | long |
| mongodb.status.locks.oplog.acquire.count.R |  | long |
| mongodb.status.locks.oplog.acquire.count.W |  | long |
| mongodb.status.locks.oplog.acquire.count.r |  | long |
| mongodb.status.locks.oplog.acquire.count.w |  | long |
| mongodb.status.locks.oplog.deadlock.count.R |  | long |
| mongodb.status.locks.oplog.deadlock.count.W |  | long |
| mongodb.status.locks.oplog.deadlock.count.r |  | long |
| mongodb.status.locks.oplog.deadlock.count.w |  | long |
| mongodb.status.locks.oplog.wait.count.R |  | long |
| mongodb.status.locks.oplog.wait.count.W |  | long |
| mongodb.status.locks.oplog.wait.count.r |  | long |
| mongodb.status.locks.oplog.wait.count.w |  | long |
| mongodb.status.locks.oplog.wait.us.R |  | long |
| mongodb.status.locks.oplog.wait.us.W |  | long |
| mongodb.status.locks.oplog.wait.us.r |  | long |
| mongodb.status.locks.oplog.wait.us.w |  | long |
| mongodb.status.memory.bits | Either 64 or 32, depending on which target architecture was specified during the mongod compilation process. | long |
| mongodb.status.memory.mapped.mb | The amount of mapped memory, in megabytes (MB), used by the database. Because MongoDB uses memory-mapped files, this value is likely to be to be roughly equivalent to the total size of your database or databases. | long |
| mongodb.status.memory.mapped_with_journal.mb | The amount of mapped memory, in megabytes (MB), including the memory used for journaling. | long |
| mongodb.status.memory.resident.mb | The amount of RAM, in megabytes (MB), currently used by the database process. | long |
| mongodb.status.memory.virtual.mb | The amount, in megabytes (MB), of virtual memory used by the mongod process. | long |
| mongodb.status.network.in.bytes | The amount of network traffic, in bytes, received by this database. | long |
| mongodb.status.network.out.bytes | The amount of network traffic, in bytes, sent from this database. | long |
| mongodb.status.network.requests | The total number of requests received by the server. | long |
| mongodb.status.ops.counters.command | The total number of commands issued to the database since the mongod instance last started. | long |
| mongodb.status.ops.counters.delete | The total number of delete operations received since the mongod instance last started. | long |
| mongodb.status.ops.counters.getmore | The total number of getmore operations received since the mongod instance last started. | long |
| mongodb.status.ops.counters.insert | The total number of insert operations received since the mongod instance last started. | long |
| mongodb.status.ops.counters.query | The total number of queries received since the mongod instance last started. | long |
| mongodb.status.ops.counters.update | The total number of update operations received since the mongod instance last started. | long |
| mongodb.status.ops.latencies.commands.count | Total number of commands performed on the collection since startup. | long |
| mongodb.status.ops.latencies.commands.latency | Total combined latency in microseconds. | long |
| mongodb.status.ops.latencies.reads.count | Total number of read operations performed on the collection since startup. | long |
| mongodb.status.ops.latencies.reads.latency | Total combined latency in microseconds. | long |
| mongodb.status.ops.latencies.writes.count | Total number of write operations performed on the collection since startup. | long |
| mongodb.status.ops.latencies.writes.latency | Total combined latency in microseconds. | long |
| mongodb.status.ops.replicated.command | The total number of replicated commands issued to the database since the mongod instance last started. | long |
| mongodb.status.ops.replicated.delete | The total number of replicated delete operations received since the mongod instance last started. | long |
| mongodb.status.ops.replicated.getmore | The total number of replicated getmore operations received since the mongod instance last started. | long |
| mongodb.status.ops.replicated.insert | The total number of replicated insert operations received since the mongod instance last started. | long |
| mongodb.status.ops.replicated.query | The total number of replicated queries received since the mongod instance last started. | long |
| mongodb.status.ops.replicated.update | The total number of replicated update operations received since the mongod instance last started. | long |
| mongodb.status.storage_engine.name | A string that represents the name of the current storage engine. | keyword |
| mongodb.status.uptime.ms | Instance uptime in milliseconds. | long |
| mongodb.status.wired_tiger.cache.dirty.bytes | Size in bytes of the dirty data in the cache. | long |
| mongodb.status.wired_tiger.cache.maximum.bytes | Maximum cache size. | long |
| mongodb.status.wired_tiger.cache.pages.evicted | Number of pages evicted from the cache. | long |
| mongodb.status.wired_tiger.cache.pages.read | Number of pages read into the cache. | long |
| mongodb.status.wired_tiger.cache.pages.write | Number of pages written from the cache. | long |
| mongodb.status.wired_tiger.cache.used.bytes | Size in byte of the data currently in cache. | long |
| mongodb.status.wired_tiger.concurrent_transactions.read.available | Number of concurrent read tickets available. | long |
| mongodb.status.wired_tiger.concurrent_transactions.read.out | Number of concurrent read transaction in progress. | long |
| mongodb.status.wired_tiger.concurrent_transactions.read.total_tickets | Number of total read tickets. | long |
| mongodb.status.wired_tiger.concurrent_transactions.write.available | Number of concurrent write tickets available. | long |
| mongodb.status.wired_tiger.concurrent_transactions.write.out | Number of concurrent write transaction in progress. | long |
| mongodb.status.wired_tiger.concurrent_transactions.write.total_tickets | Number of total write tickets. | long |
| mongodb.status.wired_tiger.log.flushes | Number of flush operations. | long |
| mongodb.status.wired_tiger.log.max_file_size.bytes | Maximum file size. | long |
| mongodb.status.wired_tiger.log.scans | Number of scan operations. | long |
| mongodb.status.wired_tiger.log.size.bytes | Total log size in bytes. | long |
| mongodb.status.wired_tiger.log.syncs | Number of sync operations. | long |
| mongodb.status.wired_tiger.log.write.bytes | Number of bytes written into the log. | long |
| mongodb.status.wired_tiger.log.writes | Number of write operations. | long |
| mongodb.status.write_backs_queued | True when there are operations from a mongos instance queued for retrying. | boolean |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| service.address | Address of the machine where the service is running. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| service.version | Version of the service the data was collected from. This allows to look at a data set only for a specific version of a service. | keyword |

