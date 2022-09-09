# VMware vSphere Integration

This integration periodically fetches logs and metrics from [vSphere](https://www.vmware.com/products/vsphere.html) vCenter servers. 

## Compatibility
The integration uses the [Govmomi](https://github.com/vmware/govmomi) library to collect metrics and logs from any Vmware SDK URL (ESXi/VCenter). This library is built for and tested against ESXi and vCenter 6.5, 6.7 and 7.0.

## Metrics

To access the metrices, the url https://host:port(8989)/sdk needs to be passed to the hosts in Kibana UI. 

### Virtual Machine Metrics

 The virtual machine consists of a set of specification and configuration files and is backed by the physical resources of a host. Every virtual machine has virtual devices that provide the same functionality as physical hardware but are more portable, secure and easier to manage.

An example event for `virtualmachine` looks as following:

```json
{
    "@timestamp": "2022-07-06T08:10:23.936Z",
    "agent": {
        "ephemeral_id": "7b1c7f41-9102-4338-8bb7-c4a8f16f8840",
        "id": "d8cbc62c-7f8c-4e0d-98a9-a953f1476f0a",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.2.0"
    },
    "data_stream": {
        "dataset": "vsphere.virtualmachine",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "d8cbc62c-7f8c-4e0d-98a9-a953f1476f0a",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "vsphere.virtualmachine",
        "duration": 77308917,
        "ingested": "2022-07-06T08:10:27Z",
        "module": "vsphere"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
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
            "kernel": "5.10.104-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "virtualmachine",
        "period": 10000
    },
    "service": {
        "address": "https://elastic-package-service_vsphere-metrics_1:8989/sdk",
        "type": "vsphere"
    },
    "vsphere": {
        "virtualmachine": {
            "cpu": {
                "used": {
                    "mhz": 0
                }
            },
            "host.hostname": "DC0_H0",
            "host.id": "host-21",
            "memory": {
                "free": {
                    "guest": {
                        "bytes": 33554432
                    }
                },
                "total": {
                    "guest": {
                        "bytes": 33554432
                    }
                },
                "used": {
                    "guest": {
                        "bytes": 0
                    },
                    "host": {
                        "bytes": 0
                    }
                }
            },
            "name": "DC0_H0_VM0",
            "os": "otherGuest"
        }
    }
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| error.message | Error message. | match_only_text |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |  |  |
| event.module | Event module | constant_keyword |  |  |
| host.architecture | Operating system architecture. | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| host.mac | Host mac addresses. | keyword |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |  |
| host.os.name | Operating system name, without the version. | keyword |  |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |
| vsphere.virtualmachine.cpu.free.mhz | Available CPU of virtualmachine in Mhz | long |  | gauge |
| vsphere.virtualmachine.cpu.total.mhz | Total CPU of virtualmachine in Mhz | long |  | counter |
| vsphere.virtualmachine.cpu.used.mhz | Used CPU of virtualmachine in Mhz | long |  | gauge |
| vsphere.virtualmachine.custom_fields | Custom fields | object |  |  |
| vsphere.virtualmachine.host.hostname | Name of the host hosting the virtualmachine | keyword |  |  |
| vsphere.virtualmachine.host.id | Id of the host hosting the virtualmachine | keyword |  |  |
| vsphere.virtualmachine.memory.free.guest.bytes | Free Memory of Guest in bytes | long | byte | gauge |
| vsphere.virtualmachine.memory.total.guest.bytes | Total Memory of Guest in bytes | long | byte | gauge |
| vsphere.virtualmachine.memory.used.guest.bytes | Used Memory of Guest in bytes | long | byte | gauge |
| vsphere.virtualmachine.memory.used.host.bytes | Used Memory of Host in bytes | long | byte | gauge |
| vsphere.virtualmachine.name | Virtual Machine name | keyword |  |  |
| vsphere.virtualmachine.network_names | Network names | keyword |  |  |
| vsphere.virtualmachine.os | Virtual Machine Operating System name | keyword |  |  |


### Host Metrics

 ESX hosts are the servers/data storage devices on which the ESX or ESXi hypervisor has been installed. One of these hosts can support multiple VMs

An example event for `host` looks as following:

```json
{
    "@timestamp": "2022-07-21T12:10:22.039Z",
    "agent": {
        "ephemeral_id": "926eb17b-191e-43c3-8064-3838e5345018",
        "id": "a64ea128-7315-4881-b39a-9c06346b9e29",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.2.0"
    },
    "data_stream": {
        "dataset": "vsphere.host",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "a64ea128-7315-4881-b39a-9c06346b9e29",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "vsphere.host",
        "duration": 119446084,
        "ingested": "2022-07-21T12:10:23Z",
        "module": "vsphere"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.20.0.7"
        ],
        "mac": [
            "02:42:ac:14:00:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.104-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "host",
        "period": 10000
    },
    "service": {
        "address": "https://elastic-package-service_vsphere-metrics_1:8989/sdk",
        "type": "vsphere"
    },
    "vsphere": {
        "host": {
            "cpu": {
                "free": {
                    "mhz": 4521
                },
                "total": {
                    "mhz": 4588
                },
                "used": {
                    "mhz": 67,
                    "pct": 1.4603313
                }
            },
            "memory": {
                "free": {
                    "bytes": 2822230016
                },
                "total": {
                    "bytes": 4294430720
                },
                "used": {
                    "bytes": 1472200704,
                    "pct": 34.281628
                }
            },
            "name": "DC0_H0",
            "network_names": [
                "VM Network"
            ]
        }
    }
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| error.message | Error message. | match_only_text |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |  |  |
| event.module | Event module | constant_keyword |  |  |
| host.architecture | Operating system architecture. | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| host.mac | Host mac addresses. | keyword |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |  |
| host.os.name | Operating system name, without the version. | keyword |  |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |
| vsphere.host.cpu.free.mhz | Free CPU of host in Mhz | long |  | gauge |
| vsphere.host.cpu.total.mhz | Total CPU of host in Mhz | long |  | counter |
| vsphere.host.cpu.used.mhz | Used CPU of host in Mhz | long |  | gauge |
| vsphere.host.cpu.used.pct | CPU Utilization % of the host | scaled_float | percent | gauge |
| vsphere.host.memory.free.bytes | Free Memory of host in bytes | long | byte | gauge |
| vsphere.host.memory.total.bytes | Total Memory of host in bytes | long | byte | gauge |
| vsphere.host.memory.used.bytes | Used Memory of host in bytes | long | byte | gauge |
| vsphere.host.memory.used.pct | Memory utilization % of the host | scaled_float | percent | gauge |
| vsphere.host.name | Host name | keyword |  |  |
| vsphere.host.network_names | Network names | keyword |  |  |


### Datastore Metrics
Datastores are logical containers, analogous to file systems, that hide specifics of physical storage and provide a uniform model for storing virtual machine files. 
An example event for `datastore` looks as following:

```json
{
    "@timestamp": "2022-07-06T08:06:49.831Z",
    "agent": {
        "ephemeral_id": "34e20210-abd8-4ef7-b216-3158638cbeab",
        "id": "d8cbc62c-7f8c-4e0d-98a9-a953f1476f0a",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.2.0"
    },
    "data_stream": {
        "dataset": "vsphere.datastore",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "d8cbc62c-7f8c-4e0d-98a9-a953f1476f0a",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "vsphere.datastore",
        "duration": 52476083,
        "ingested": "2022-07-06T08:06:50Z",
        "module": "vsphere"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
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
            "kernel": "5.10.104-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "datastore",
        "period": 10000
    },
    "service": {
        "address": "https://elastic-package-service_vsphere-metrics_1:8989/sdk",
        "type": "vsphere"
    },
    "vsphere": {
        "datastore": {
            "capacity": {
                "free": {
                    "bytes": 10952166604800
                },
                "total": {
                    "bytes": 10995116277760
                },
                "used": {
                    "bytes": 42949672960,
                    "pct": 0.00390625
                }
            },
            "fstype": "OTHER",
            "name": "LocalDS_0"
        }
    }
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| error.message | Error message. | match_only_text |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |  |  |
| event.module | Event module | constant_keyword |  |  |
| host.architecture | Operating system architecture. | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| host.mac | Host mac addresses. | keyword |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |  |
| host.os.name | Operating system name, without the version. | keyword |  |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |
| vsphere.datastore.capacity.free.bytes | Free bytes of the datastore | long | byte | gauge |
| vsphere.datastore.capacity.total.bytes | Total bytes of the datastore | long | byte | gauge |
| vsphere.datastore.capacity.used.bytes | Used bytes of the datastore | long | byte | gauge |
| vsphere.datastore.capacity.used.pct | Used percent of the datastore | scaled_float | percent | gauge |
| vsphere.datastore.fstype | Filesystem type | keyword |  |  |
| vsphere.datastore.name | Datastore name | keyword |  |  |


## Logs

To access the logs, host address (localhost) and host port (9525) needs to be passed in Kibana UI. 

### vSphere Logs

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
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
| hostname | Hostname from syslog header. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.logger | The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name. | keyword |
| log.source.address | Source address of the syslog message. | keyword |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.pid | Process id. | long |
| process.program | Process from syslog header. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| vsphere.log.datacenter |  | keyword |

