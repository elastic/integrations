# VMware vSphere Integration

This integration periodically fetches logs and metrics from [vSphere](https://www.vmware.com/products/vsphere.html) vCenter servers. 

## Compatibility
The integration uses the [Govmomi](https://github.com/vmware/govmomi) library to collect metrics and logs from any Vmware SDK URL (ESXi/VCenter). This library is built for and tested against ESXi and vCenter 6.5, 6.7 and 7.0.

## Metrics

To access the metrices, the url https://host:port(8989)/sdk needs to be passed to the hosts in Kibana UI. 

### Virtual Machine Metrics

 The virtual machine consists of a set of specification and configuration files and is backed by the physical resources of a host. Every virtual machine has virtual devices that provide the same functionality as physical hardware but are more portable, secure and easier to manage.

 Note: vSphere Integration currently supports network names of VMs connected only to vSS (vSphere Standard Switch) and not vDS (vSphere Distributed Switches).

An example event for `virtualmachine` looks as following:

```json
{
    "@timestamp": "2023-06-29T08:06:40.827Z",
    "agent": {
        "ephemeral_id": "527dd76f-fe04-4478-b02c-110b5f47ccf4",
        "id": "5096d7cc-1e4b-4959-abea-7355be2913a7",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.8.1"
    },
    "data_stream": {
        "dataset": "vsphere.virtualmachine",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "5096d7cc-1e4b-4959-abea-7355be2913a7",
        "snapshot": false,
        "version": "8.8.1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "vsphere.virtualmachine",
        "duration": 14355583,
        "ingested": "2023-06-29T08:06:41Z",
        "module": "vsphere"
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "d08b346fbb8f49f5a2bb1a477f8ceb54",
        "ip": [
            "172.23.0.7"
        ],
        "mac": [
            "02-42-AC-17-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.104-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
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
            "host": {
                "hostname": "DC0_H0",
                "id": "host-21"
            },
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

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id |  | keyword |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.name | Name of the host.  It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
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
    "@timestamp": "2023-06-29T08:04:19.217Z",
    "agent": {
        "ephemeral_id": "7528b4c0-2fe5-42c3-ab9d-6e57cdf00a5f",
        "id": "5096d7cc-1e4b-4959-abea-7355be2913a7",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.8.1"
    },
    "data_stream": {
        "dataset": "vsphere.host",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "5096d7cc-1e4b-4959-abea-7355be2913a7",
        "snapshot": false,
        "version": "8.8.1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "vsphere.host",
        "duration": 45720334,
        "ingested": "2023-06-29T08:04:22Z",
        "module": "vsphere"
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "d08b346fbb8f49f5a2bb1a477f8ceb54",
        "ip": [
            "172.23.0.7"
        ],
        "mac": [
            "02-42-AC-17-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.104-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
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
                    "pct": 0.015
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
                    "pct": 0.343
                }
            },
            "name": "DC0_H0",
            "network_names": "VM Network"
        }
    }
}
```

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id |  | keyword |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.name | Name of the host.  It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
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
    "@timestamp": "2023-06-29T08:03:30.114Z",
    "agent": {
        "ephemeral_id": "8b019ff3-cbda-41fa-b1ff-974d482b9694",
        "id": "5096d7cc-1e4b-4959-abea-7355be2913a7",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.8.1"
    },
    "data_stream": {
        "dataset": "vsphere.datastore",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "5096d7cc-1e4b-4959-abea-7355be2913a7",
        "snapshot": false,
        "version": "8.8.1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "vsphere.datastore",
        "duration": 23155458,
        "ingested": "2023-06-29T08:03:31Z",
        "module": "vsphere"
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "d08b346fbb8f49f5a2bb1a477f8ceb54",
        "ip": [
            "172.23.0.7"
        ],
        "mac": [
            "02-42-AC-17-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.104-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
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
                    "bytes": 47869427712
                },
                "total": {
                    "bytes": 62725623808
                },
                "used": {
                    "bytes": 14856196096,
                    "pct": 0.237
                }
            },
            "fstype": "OTHER",
            "name": "LocalDS_0"
        }
    }
}
```

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id |  | keyword |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.name | Name of the host.  It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| vsphere.datastore.capacity.free.bytes | Free bytes of the datastore | long | byte | gauge |
| vsphere.datastore.capacity.total.bytes | Total bytes of the datastore | long | byte | gauge |
| vsphere.datastore.capacity.used.bytes | Used bytes of the datastore | long | byte | gauge |
| vsphere.datastore.capacity.used.pct | Used percent of the datastore | scaled_float | percent | gauge |
| vsphere.datastore.fstype | Filesystem type | keyword |  |  |
| vsphere.datastore.name | Datastore name | keyword |  |  |


## Logs

To collect logs, a syslog daemon is used. First, you must configure the listening host/IP address (default: localhost) and host port (default: 9525) in the integration. Then, configure vSphere to send logs to a remote syslog host and provide the configured hostname/IP and port of the Elastic Agent host.

### vSphere Logs

## ECS Field Reference

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
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| hostname | Hostname from syslog header. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.source.address | Source address of the syslog message. | keyword |
| process.program | Process from syslog header. | keyword |
| vsphere.log.api.invocations |  | long |
| vsphere.log.datacenter |  | keyword |
| vsphere.log.file.path |  | keyword |

