# Apache Integration

This integration periodically fetches logs and metrics from [vSphere](https://www.vmware.com/products/vsphere.html) vCenter servers. 

## Compatibility

The vSphere datasets were tested with vCenter 6.7.0.31000 and are expected to work with all versions >= 6.7.

## Logs

vSphere logs

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |


## Metrics

### Virtual Machine Metrics

An example event for `virtualmachine` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "event": {
        "dataset": "vsphere.virtualmachine",
        "duration": 115000,
        "module": "vsphere"
    },
    "metricset": {
        "name": "virtualmachine",
        "period": 10000
    },
    "service": {
        "address": "127.0.0.1:39149",
        "type": "vsphere"
    },
    "vsphere": {
        "virtualmachine": {
            "cpu": {
                "used": {
                    "mhz": 0
                }
            },
            "host.hostname": "localhost.localdomain",
            "host.id": "ha-host",
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
            "name": "ha-host_VM0",
            "os": "otherGuest"
        }
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
| ecs.version | ECS version | keyword |
| error.message | Error message. | text |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.address | Service address | keyword |
| service.type | Service type | keyword |
| vsphere.virtualmachine.cpu.free.mhz | Available CPU in Mhz | long |
| vsphere.virtualmachine.cpu.total.mhz | Total CPU in Mhz | long |
| vsphere.virtualmachine.cpu.used.mhz | Used CPU in Mhz | long |
| vsphere.virtualmachine.custom_fields | Custom fields | object |
| vsphere.virtualmachine.host.hostname | Host name of the host | keyword |
| vsphere.virtualmachine.host.id | Host id | keyword |
| vsphere.virtualmachine.memory.free.guest.bytes | Free Memory of Guest in bytes | long |
| vsphere.virtualmachine.memory.total.guest.bytes | Total Memory of Guest in bytes | long |
| vsphere.virtualmachine.memory.used.guest.bytes | Used Memory of Guest in bytes | long |
| vsphere.virtualmachine.memory.used.host.bytes | Used Memory of Host in bytes | long |
| vsphere.virtualmachine.name | Virtual Machine name | keyword |
| vsphere.virtualmachine.network_names | Network names | keyword |
| vsphere.virtualmachine.os | Virtual Machine Operating System name | keyword |


### Host Metrics

An example event for `host` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "event": {
        "dataset": "vsphere.host",
        "duration": 115000,
        "module": "vsphere"
    },
    "metricset": {
        "name": "host",
        "period": 10000
    },
    "service": {
        "address": "127.0.0.1:38517",
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
                    "mhz": 67
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
                    "bytes": 1472200704
                }
            },
            "name": "localhost.localdomain"
        }
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
| ecs.version | ECS version | keyword |
| error.message | Error message. | text |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.address | Service address | keyword |
| service.type | Service type | keyword |
| vsphere.host.cpu.free.mhz | Free CPU in Mhz | long |
| vsphere.host.cpu.total.mhz | Total CPU in Mhz | long |
| vsphere.host.cpu.used.mhz | Used CPU in Mhz | long |
| vsphere.host.memory.free.bytes | Free Memory in bytes | long |
| vsphere.host.memory.total.bytes | Total Memory in bytes | long |
| vsphere.host.memory.used.bytes | Used Memory in bytes | long |
| vsphere.host.name | Host name | keyword |
| vsphere.host.network_names | Network names | keyword |


### Datastore Metrics

An example event for `datastore` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "event": {
        "dataset": "vsphere.datastore",
        "duration": 115000,
        "module": "vsphere"
    },
    "metricset": {
        "name": "datastore",
        "period": 10000
    },
    "service": {
        "address": "127.0.0.1:33365",
        "type": "vsphere"
    },
    "vsphere": {
        "datastore": {
            "capacity": {
                "free": {
                    "bytes": 37120094208
                },
                "total": {
                    "bytes": 74686664704
                },
                "used": {
                    "bytes": 37566570496,
                    "pct": 0.502988996026061
                }
            },
            "fstype": "local",
            "name": "LocalDS_0"
        }
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
| ecs.version | ECS version | keyword |
| error.message | Error message. | text |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.address | Service address | keyword |
| service.type | Service type | keyword |
| vsphere.datastore.capacity.free.bytes | Free bytes of the datastore | long |
| vsphere.datastore.capacity.total.bytes | Total bytes of the datastore | long |
| vsphere.datastore.capacity.used.bytes | Used bytes of the datastore | long |
| vsphere.datastore.capacity.used.pct | Used percent of the datastore | scaled_float |
| vsphere.datastore.fstype | Filesystem type | keyword |
| vsphere.datastore.name | Datastore name | keyword |
