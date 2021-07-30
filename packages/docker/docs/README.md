# Docker Integration

This Integration fetches metrics from [Docker](https://www.docker.com/) containers. The default data streams are: `container`, `cpu`, `diskio`, `healthcheck`, `info`, `memory` and `network`. The `image` metricset is not enabled by default.

## Compatibility

The Docker module is currently tested on Linux and Mac with the community
edition engine, versions 1.11 and 17.09.0-ce. It is not tested on Windows,
but it should also work there.

## Running from within Docker

The `docker` Integration will try to connect to the docker socket, by default at `unix:///var/run/docker.sock`.
If Elastic Agent is running inside docker, you'll need to mount the unix socket inside the container:

```
docker run -d \
  --name=metricbeat \
  --user=root \
  --volume="/var/run/docker.sock:/var/run/docker.sock:ro" \
  docker.elastic.co/beats/metricbeat:latest metricbeat -e \
  -E output.elasticsearch.hosts=["elasticsearch:9200"]
```

## Module-specific configuration notes

It is strongly recommended that you run Docker metricsets with a
[`period`](https://www.elastic.co/guide/en/beats/metricbeat/current/configuration-metricbeat.html#metricset-period)
that is 3 seconds or longer. The request to the
Docker API already takes up to 2 seconds. Specifying less than 3 seconds will
result in requests that timeout, and no data will be reported for those
requests.

## Metrics

### Container

The Docker `container` data stream collects information and statistics about
running Docker containers.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| container.id | Unique container id. | keyword |  |
| container.image.name | Name of the image the container was built on. | keyword |  |
| container.name | Container name. | keyword |  |
| container.runtime | Container runtime. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| docker.container.command | Command that was executed in the Docker container. | keyword |  |
| docker.container.created | Date when the container was created. | date |  |
| docker.container.ip_addresses | Container IP addresses. | ip |  |
| docker.container.labels.\* | Container labels | object |  |
| docker.container.size.root_fs | Total size of all the files in the container. | long | gauge |
| docker.container.size.rw | Size of the files that have been created or changed since creation. | long | gauge |
| docker.container.status | Container status. | keyword |  |
| docker.container.tags | Image tags. | keyword |  |
| ecs.version | ECS version | keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.architecture | Operating system architecture. | keyword |  |
| host.ip | Host ip address. | ip |  |
| host.mac | Host mac address. | keyword |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |
| host.os.full | Operating system name, including the version or code name. | keyword |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |
| host.os.name | Operating system name, without the version. | keyword |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |
| host.os.version | Operating system version as a raw string. | keyword |  |
| host.type | Type of host. | keyword |  |
| service.address | Service address | keyword |  |
| service.type | Service type | keyword |  |


An example event for `container` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "agent": {
        "hostname": "host.example.com",
        "name": "host.example.com"
    },
    "container": {
        "id": "cc78e58acfda4501105dc4de8e3ae218f2da616213e6e3af168c40103829302a",
        "image": {
            "name": "metricbeat_elasticsearch"
        },
        "name": "metricbeat_elasticsearch_1_df866b3a7b3d",
        "runtime": "docker"
    },
    "docker": {
        "container": {
            "command": "/usr/local/bin/docker-entrypoint.sh eswrapper",
            "created": "2019-02-25T10:18:10.000Z",
            "ip_addresses": [
                "172.23.0.2"
            ],
            "labels": {
                "com_docker_compose_config-hash": "e3e0a2c6e5d1afb741bc8b1ecb09cda0395886b7a3e5084a9fd110be46d70f78",
                "com_docker_compose_container-number": "1",
                "com_docker_compose_oneoff": "False",
                "com_docker_compose_project": "metricbeat",
                "com_docker_compose_service": "elasticsearch",
                "com_docker_compose_slug": "df866b3a7b3d50c0802350cbe58ee5b34fa32b7f6ba7fe9e48cde2c12dd0201d",
                "com_docker_compose_version": "1.23.1",
                "license": "Elastic License",
                "org_label-schema_build-date": "20181006",
                "org_label-schema_license": "GPLv2",
                "org_label-schema_name": "elasticsearch",
                "org_label-schema_schema-version": "1.0",
                "org_label-schema_url": "https://www.elastic.co/products/elasticsearch",
                "org_label-schema_vcs-url": "https://github.com/elastic/elasticsearch-docker",
                "org_label-schema_vendor": "Elastic",
                "org_label-schema_version": "6.5.1"
            },
            "size": {
                "root_fs": 0,
                "rw": 0
            },
            "status": "Up 7 minutes (healthy)"
        }
    },
    "event": {
        "dataset": "docker.container",
        "duration": 115000,
        "module": "docker"
    },
    "metricset": {
        "name": "container"
    },
    "service": {
        "address": "/var/run/docker.sock",
        "type": "docker"
    }
}
```

### CPU

The Docker `cpu` data stream collects runtime CPU metrics.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| container.id | Unique container id. | keyword |  |  |
| container.image.name | Name of the image the container was built on. | keyword |  |  |
| container.name | Container name. | keyword |  |  |
| container.runtime | Container runtime. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| docker.container.labels.\* | Container labels | object |  |  |
| docker.cpu.core.\*.norm.pct | Percentage of CPU time in this core, normalized by the number of CPU cores. | scaled_float | percent | gauge |
| docker.cpu.core.\*.pct | Percentage of CPU time in this core. | scaled_float | percent | gauge |
| docker.cpu.core.\*.ticks | Number of CPU ticks in this core. | long |  | counter |
| docker.cpu.kernel.norm.pct | Percentage of time in kernel space normalized by the number of CPU cores. | scaled_float | percent | gauge |
| docker.cpu.kernel.pct | Percentage of time in kernel space. | scaled_float | percent | gauge |
| docker.cpu.kernel.ticks | CPU ticks in kernel space. | long |  | counter |
| docker.cpu.system.norm.pct | Percentage of total CPU time in the system normalized by the number of CPU cores. | scaled_float | percent | gauge |
| docker.cpu.system.pct | Percentage of total CPU time in the system. | scaled_float | percent | gauge |
| docker.cpu.system.ticks | CPU system ticks. | long |  | counter |
| docker.cpu.total.norm.pct | Total CPU usage normalized by the number of CPU cores. | scaled_float | percent | gauge |
| docker.cpu.total.pct | Total CPU usage. | scaled_float | percent | gauge |
| docker.cpu.user.norm.pct | Percentage of time in user space normalized by the number of CPU cores. | scaled_float | percent | gauge |
| docker.cpu.user.pct | Percentage of time in user space. | scaled_float | percent | gauge |
| docker.cpu.user.ticks | CPU ticks in user space. | long |  | counter |
| ecs.version | ECS version | keyword |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| host.architecture | Operating system architecture. | keyword |  |  |
| host.ip | Host ip address. | ip |  |  |
| host.mac | Host mac address. | keyword |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |  |
| host.os.full | Operating system name, including the version or code name. | keyword |  |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |  |
| host.os.name | Operating system name, without the version. | keyword |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. | keyword |  |  |
| service.address | Service address | keyword |  |  |
| service.type | Service type | keyword |  |  |


An example event for `cpu` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "container": {
        "id": "7f3ca1f1b2b310362e90f700d2b2e52ebd46ef6ddf10c0704f22b25686c466ab",
        "image": {
            "name": "metricbeat_beat"
        },
        "name": "metricbeat_beat_run_8ba23fa682a6",
        "runtime": "docker"
    },
    "docker": {
        "container": {
            "labels": {
                "com_docker_compose_oneoff": "True",
                "com_docker_compose_project": "metricbeat",
                "com_docker_compose_service": "beat",
                "com_docker_compose_slug": "8ba23fa682a68e2dc082536da22f59eb2d200b3534909fe934807dd5d847424",
                "com_docker_compose_version": "1.24.1"
            }
        },
        "cpu": {
            "core": {
                "0": {
                    "norm": {
                        "pct": 0.00105707400990099
                    },
                    "pct": 0.00845659207920792,
                    "ticks": 7410396430
                },
                "1": {
                    "norm": {
                        "pct": 0.004389216831683168
                    },
                    "pct": 0.035113734653465345,
                    "ticks": 7079258391
                },
                "2": {
                    "norm": {
                        "pct": 0.003178435024752475
                    },
                    "pct": 0.0254274801980198,
                    "ticks": 7140978706
                },
                "3": {
                    "norm": {
                        "pct": 0.0033261257425742574
                    },
                    "pct": 0.02660900594059406,
                    "ticks": 7705738146
                },
                "4": {
                    "norm": {
                        "pct": 0.0016827236386138613
                    },
                    "pct": 0.01346178910891089,
                    "ticks": 8131054429
                },
                "5": {
                    "norm": {
                        "pct": 0.000781541707920792
                    },
                    "pct": 0.006252333663366336,
                    "ticks": 7213899699
                },
                "6": {
                    "norm": {
                        "pct": 0.0005364748762376238
                    },
                    "pct": 0.00429179900990099,
                    "ticks": 7961016581
                },
                "7": {
                    "norm": {
                        "pct": 0.0005079449257425743
                    },
                    "pct": 0.004063559405940594,
                    "ticks": 7946529895
                }
            },
            "kernel": {
                "norm": {
                    "pct": 0.007425742574257425
                },
                "pct": 0.0594059405940594,
                "ticks": 26810000000
            },
            "system": {
                "norm": {
                    "pct": 1
                },
                "pct": 8,
                "ticks": 65836400000000
            },
            "total": {
                "norm": {
                    "pct": 0.015459536757425743
                },
                "pct": 0.12367629405940594
            },
            "user": {
                "norm": {
                    "pct": 0.006188118811881188
                },
                "pct": 0.04950495049504951,
                "ticks": 35720000000
            }
        }
    },
    "event": {
        "dataset": "docker.cpu",
        "duration": 115000,
        "module": "docker"
    },
    "metricset": {
        "name": "cpu",
        "period": 10000
    },
    "service": {
        "address": "/var/run/docker.sock",
        "type": "docker"
    }
}
```

### Diskio

The Docker `diskio` data stream collects disk I/O metrics.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| container.id | Unique container id. | keyword |  |  |
| container.image.name | Name of the image the container was built on. | keyword |  |  |
| container.name | Container name. | keyword |  |  |
| container.runtime | Container runtime. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| docker.container.labels.\* | Container labels | object |  |  |
| docker.diskio.read.bytes | Bytes read during the life of the container | long |  | counter |
| docker.diskio.read.ops | Number of reads during the life of the container | long |  |  |
| docker.diskio.read.queued | Total number of queued requests | long |  | gauge |
| docker.diskio.read.rate | Number of current reads per second | long |  | gauge |
| docker.diskio.read.service_time | Total time to service IO requests, in nanoseconds | long |  | counter |
| docker.diskio.read.wait_time | Total time requests spent waiting in queues for service, in nanoseconds | long |  | counter |
| docker.diskio.reads | Number of current reads per second | scaled_float |  | gauge |
| docker.diskio.summary.bytes | Bytes read and written during the life of the container | long | byte | counter |
| docker.diskio.summary.ops | Number of I/O operations during the life of the container | long |  | counter |
| docker.diskio.summary.queued | Total number of queued requests | long |  | counter |
| docker.diskio.summary.rate | Number of current operations per second | long |  | gauge |
| docker.diskio.summary.service_time | Total time to service IO requests, in nanoseconds | long |  | counter |
| docker.diskio.summary.wait_time | Total time requests spent waiting in queues for service, in nanoseconds | long |  | counter |
| docker.diskio.total | Number of reads and writes per second | scaled_float |  | gauge |
| docker.diskio.write.bytes | Bytes written during the life of the container | long | byte | counter |
| docker.diskio.write.ops | Number of writes during the life of the container | long |  | counter |
| docker.diskio.write.queued | Total number of queued requests | long |  | counter |
| docker.diskio.write.rate | Number of current writes per second | long |  | gauge |
| docker.diskio.write.service_time | Total time to service IO requests, in nanoseconds | long |  | counter |
| docker.diskio.write.wait_time | Total time requests spent waiting in queues for service, in nanoseconds | long |  | counter |
| docker.diskio.writes | Number of current writes per second | scaled_float |  | gauge |
| ecs.version | ECS version | keyword |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| host.architecture | Operating system architecture. | keyword |  |  |
| host.ip | Host ip address. | ip |  |  |
| host.mac | Host mac address. | keyword |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |  |
| host.os.full | Operating system name, including the version or code name. | keyword |  |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |  |
| host.os.name | Operating system name, without the version. | keyword |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. | keyword |  |  |
| service.address | Service address | keyword |  |  |
| service.type | Service type | keyword |  |  |


An example event for `diskio` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "container": {
        "id": "8abaa1f3514d3554503034a1df6ee09457f328757bbc9555245244ee853c0b44",
        "image": {
            "name": "zookeeper"
        },
        "name": "some-zookeeper",
        "runtime": "docker"
    },
    "docker": {
        "diskio": {
            "read": {
                "bytes": 42409984,
                "ops": 1823,
                "queued": 0,
                "rate": 0,
                "service_time": 0,
                "wait_time": 0
            },
            "reads": 0,
            "summary": {
                "bytes": 42414080,
                "ops": 1824,
                "queued": 0,
                "rate": 0,
                "service_time": 0,
                "wait_time": 0
            },
            "total": 0,
            "write": {
                "bytes": 4096,
                "ops": 1,
                "queued": 0,
                "rate": 0,
                "service_time": 0,
                "wait_time": 0
            },
            "writes": 0
        }
    },
    "event": {
        "dataset": "docker.diskio",
        "duration": 115000,
        "module": "docker"
    },
    "metricset": {
        "name": "diskio",
        "period": 10000
    },
    "service": {
        "address": "/var/run/docker.sock",
        "type": "docker"
    }
}
```

### Event

The Docker `event` data stream collects docker events

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.name | Container name. | keyword |
| container.runtime | Container runtime. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| docker.container.labels.\* | Container labels | object |
| docker.event.action | The type of event | keyword |
| docker.event.actor.attributes | Various key/value attributes of the object, depending on its type | flattened |
| docker.event.actor.id | The ID of the object emitting the event | keyword |
| docker.event.from | Event source | keyword |
| docker.event.id | Event id when available | keyword |
| docker.event.status | Event status | keyword |
| docker.event.type | The type of object emitting the event | keyword |
| ecs.version | ECS version | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.architecture | Operating system architecture. | keyword |
| host.ip | Host ip address. | ip |
| host.mac | Host mac address. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.full | Operating system name, including the version or code name. | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. | keyword |
| service.address | Service address | keyword |
| service.type | Service type | keyword |


An example event for `event` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "agent": {
        "hostname": "host.example.com",
        "name": "host.example.com"
    },
    "docker": {
        "event": {
            "action": "pull",
            "actor": {
                "attributes": {
                    "name": "busybox"
                },
                "id": "busybox:latest"
            },
            "from": "",
            "id": "busybox:latest",
            "status": "pull",
            "type": "image"
        }
    },
    "event": {
        "dataset": "docker.event",
        "module": "docker"
    },
    "service": {
        "type": "docker"
    }
}
```

### Healthcheck

The Docker `healthcheck` data stream collects healthcheck status metrics about
running Docker containers.

Healthcheck data will only be available from docker containers where the
docker `HEALTHCHECK` instruction has been used to build the docker image.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| container.id | Unique container id. | keyword |  |
| container.image.name | Name of the image the container was built on. | keyword |  |
| container.name | Container name. | keyword |  |
| container.runtime | Container runtime. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| docker.container.labels.\* | Container labels | object |  |
| docker.healthcheck.event.end_date | Healthcheck end date | date |  |
| docker.healthcheck.event.exit_code | Healthcheck status code | integer |  |
| docker.healthcheck.event.output | Healthcheck output | keyword |  |
| docker.healthcheck.event.start_date | Healthcheck start date | date |  |
| docker.healthcheck.failingstreak | concurent failed check | integer | counter |
| docker.healthcheck.status | Healthcheck status code | keyword |  |
| ecs.version | ECS version | keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.architecture | Operating system architecture. | keyword |  |
| host.ip | Host ip address. | ip |  |
| host.mac | Host mac address. | keyword |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |
| host.os.full | Operating system name, including the version or code name. | keyword |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |
| host.os.name | Operating system name, without the version. | keyword |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |
| host.os.version | Operating system version as a raw string. | keyword |  |
| host.type | Type of host. | keyword |  |
| service.address | Service address | keyword |  |
| service.type | Service type | keyword |  |


An example event for `healthcheck` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "agent": {
        "hostname": "host.example.com",
        "name": "host.example.com"
    },
    "container": {
        "id": "cc78e58acfda4501105dc4de8e3ae218f2da616213e6e3af168c40103829302a",
        "image": {
            "name": "metricbeat_elasticsearch"
        },
        "name": "metricbeat_elasticsearch_1_df866b3a7b3d",
        "runtime": "docker"
    },
    "docker": {
        "container": {
            "labels": {
                "com_docker_compose_config-hash": "e3e0a2c6e5d1afb741bc8b1ecb09cda0395886b7a3e5084a9fd110be46d70f78",
                "com_docker_compose_container-number": "1",
                "com_docker_compose_oneoff": "False",
                "com_docker_compose_project": "metricbeat",
                "com_docker_compose_service": "elasticsearch",
                "com_docker_compose_slug": "df866b3a7b3d50c0802350cbe58ee5b34fa32b7f6ba7fe9e48cde2c12dd0201d",
                "com_docker_compose_version": "1.23.1",
                "license": "Elastic License",
                "org_label-schema_build-date": "20181006",
                "org_label-schema_license": "GPLv2",
                "org_label-schema_name": "elasticsearch",
                "org_label-schema_schema-version": "1.0",
                "org_label-schema_url": "https://www.elastic.co/products/elasticsearch",
                "org_label-schema_vcs-url": "https://github.com/elastic/elasticsearch-docker",
                "org_label-schema_vendor": "Elastic",
                "org_label-schema_version": "6.5.1"
            }
        },
        "healthcheck": {
            "event": {
                "end_date": "2019-02-25T10:59:07.472Z",
                "exit_code": 0,
                "output": "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n                                 Dload  Upload   Total   Spent    Left  Speed\n\r  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0\r100   338  100   338    0     0  13188      0 --:--:-- --:--:-- --:--:-- 13520\n{\n  \"license\" : {\n    \"status\" : \"active\",\n    \"uid\" : \"ea5a516e-d9ee-4131-8eec-b39741e80869\",\n    \"type\" : \"basic\",\n    \"issue_date\" : \"2019-02-25T10:18:24.885Z\",\n    \"issue_date_in_millis\" : 1551089904885,\n    \"max_nodes\" : 1000,\n    \"issued_to\" : \"docker-cluster\",\n    \"issuer\" : \"elasticsearch\",\n    \"start_date_in_millis\" : -1\n  }\n}\n",
                "start_date": "2019-02-25T10:59:07.342Z"
            },
            "failingstreak": 0,
            "status": "healthy"
        }
    },
    "event": {
        "dataset": "docker.healthcheck",
        "duration": 115000,
        "module": "docker"
    },
    "metricset": {
        "name": "healthcheck"
    },
    "service": {
        "address": "/var/run/docker.sock",
        "type": "docker"
    }
}
```

### Image

The Docker `image` data stream collects metrics on docker images

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| container.id | Unique container id. | keyword |  |
| container.image.name | Name of the image the container was built on. | keyword |  |
| container.name | Container name. | keyword |  |
| container.runtime | Container runtime. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| docker.image.created | Date and time when the image was created. | date |  |
| docker.image.id.current | Unique image identifier given upon its creation. | keyword |  |
| docker.image.id.parent | Identifier of the image, if it exists, from which the current image directly descends. | keyword |  |
| docker.image.labels.\* | Image labels. | object |  |
| docker.image.size.regular | Total size of the all cached images associated to the current image. | long | counter |
| docker.image.size.virtual | Size of the image. | long | gauge |
| docker.image.tags | Image tags. | keyword |  |
| ecs.version | ECS version | keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.architecture | Operating system architecture. | keyword |  |
| host.ip | Host ip address. | ip |  |
| host.mac | Host mac address. | keyword |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |
| host.os.full | Operating system name, including the version or code name. | keyword |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |
| host.os.name | Operating system name, without the version. | keyword |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |
| host.os.version | Operating system version as a raw string. | keyword |  |
| host.type | Type of host. | keyword |  |
| service.address | Service address | keyword |  |
| service.type | Service type | keyword |  |


An example event for `image` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "docker": {
        "image": {
            "created": "2019-03-25T09:57:14.000Z",
            "id": {
                "current": "sha256:fa96dbd9baead0b3a4550c861cc871f40c0c7482889fb5f09c705e7d0622358f",
                "parent": ""
            },
            "labels": {
                "license": "Elastic License",
                "org_label-schema_build-date": "20190305",
                "org_label-schema_license": "GPLv2",
                "org_label-schema_name": "logstash",
                "org_label-schema_schema-version": "1.0",
                "org_label-schema_url": "https://www.elastic.co/products/logstash",
                "org_label-schema_vcs-url": "https://github.com/elastic/logstash-docker",
                "org_label-schema_vendor": "Elastic",
                "org_label-schema_version": "8.0.0-SNAPSHOT"
            },
            "size": {
                "regular": 770558778,
                "virtual": 770558778
            },
            "tags": [
                "docker.elastic.co/logstash/logstash:8.0.0-SNAPSHOT"
            ]
        }
    },
    "event": {
        "dataset": "docker.image",
        "duration": 115000,
        "module": "docker"
    },
    "metricset": {
        "name": "image"
    },
    "service": {
        "address": "/var/run/docker.sock",
        "type": "docker"
    }
}
```

### Info

The Docker `info` data stream collects system-wide information based on the
https://docs.docker.com/engine/reference/api/docker_remote_api_v1.24/#/display-system-wide-information[Docker Remote API].

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| container.id | Unique container id. | keyword |  |
| container.image.name | Name of the image the container was built on. | keyword |  |
| container.name | Container name. | keyword |  |
| container.runtime | Container runtime. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| docker.info.containers.paused | Total number of paused containers. | long | counter |
| docker.info.containers.running | Total number of running containers. | long | counter |
| docker.info.containers.stopped | Total number of stopped containers. | long | counter |
| docker.info.containers.total | Total number of existing containers. | long | counter |
| docker.info.id | Unique Docker host identifier. | keyword |  |
| docker.info.images | Total number of existing images. | long | counter |
| ecs.version | ECS version | keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.architecture | Operating system architecture. | keyword |  |
| host.ip | Host ip address. | ip |  |
| host.mac | Host mac address. | keyword |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |
| host.os.full | Operating system name, including the version or code name. | keyword |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |
| host.os.name | Operating system name, without the version. | keyword |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |
| host.os.version | Operating system version as a raw string. | keyword |  |
| host.type | Type of host. | keyword |  |
| service.address | Service address | keyword |  |
| service.type | Service type | keyword |  |


An example event for `info` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "docker": {
        "info": {
            "containers": {
                "paused": 0,
                "running": 2,
                "stopped": 12,
                "total": 14
            },
            "id": "VF5E:SKD6:YFIG:VDGO:JU3M:ZT2N:4E6B:7IOL:5QOS:M3HT:EM7E:VL22",
            "images": 425
        }
    },
    "event": {
        "dataset": "docker.info",
        "duration": 115000,
        "module": "docker"
    },
    "metricset": {
        "name": "info",
        "period": 10000
    },
    "service": {
        "address": "/var/run/docker.sock",
        "type": "docker"
    }
}
```

### Memory

The Docker `memory` data stream collects memory metrics from docker.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| container.id | Unique container id. | keyword |  |  |
| container.image.name | Name of the image the container was built on. | keyword |  |  |
| container.name | Container name. | keyword |  |  |
| container.runtime | Container runtime. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| docker.container.labels.\* | Container labels | object |  |  |
| docker.memory.commit.peak | Peak committed bytes on Windows | long | byte | gauge |
| docker.memory.commit.total | Total bytes | long | byte | counter |
| docker.memory.fail.count | Fail counter. | scaled_float |  | counter |
| docker.memory.limit | Memory limit. | long | byte | gauge |
| docker.memory.private_working_set.total | private working sets on Windows | long | byte | gauge |
| docker.memory.rss.pct | Memory resident set size percentage. | scaled_float | percent | gauge |
| docker.memory.rss.total | Total memory resident set size. | long | byte | gauge |
| docker.memory.stats.\* | Raw memory stats from the cgroups memory.stat interface | object |  |  |
| docker.memory.usage.max | Max memory usage. | long | byte | gauge |
| docker.memory.usage.pct | Memory usage percentage. | scaled_float | percent | gauge |
| docker.memory.usage.total | Total memory usage. | long | byte | gauge |
| ecs.version | ECS version | keyword |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| host.architecture | Operating system architecture. | keyword |  |  |
| host.ip | Host ip address. | ip |  |  |
| host.mac | Host mac address. | keyword |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |  |
| host.os.full | Operating system name, including the version or code name. | keyword |  |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |  |
| host.os.name | Operating system name, without the version. | keyword |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. | keyword |  |  |
| service.address | Service address | keyword |  |  |
| service.type | Service type | keyword |  |  |


An example event for `memory` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "container": {
        "id": "aa41902101351f415e6e983b0673c0ba715dd4bc316bd5fc0ebd6fcf94287f86",
        "image": {
            "name": "redis:latest"
        },
        "name": "amazing_cohen",
        "runtime": "docker"
    },
    "docker": {
        "memory": {
            "fail": {
                "count": 0
            },
            "limit": 2095878144,
            "rss": {
                "pct": 0.0004025882909345325,
                "total": 843776
            },
            "stats": {
                "active_anon": 421888,
                "active_file": 36864,
                "cache": 86016,
                "dirty": 0,
                "hierarchical_memory_limit": 9223372036854771712,
                "hierarchical_memsw_limit": 9223372036854771712,
                "inactive_anon": 421888,
                "inactive_file": 49152,
                "mapped_file": 53248,
                "pgfault": 1587,
                "pgmajfault": 1,
                "pgpgin": 2426,
                "pgpgout": 2199,
                "rss": 843776,
                "rss_huge": 0,
                "total_active_anon": 421888,
                "total_active_file": 36864,
                "total_cache": 86016,
                "total_dirty": 0,
                "total_inactive_anon": 421888,
                "total_inactive_file": 49152,
                "total_mapped_file": 53248,
                "total_pgfault": 1587,
                "total_pgmajfault": 1,
                "total_pgpgin": 2426,
                "total_pgpgout": 2199,
                "total_rss": 843776,
                "total_rss_huge": 0,
                "total_unevictable": 0,
                "total_writeback": 0,
                "unevictable": 0,
                "writeback": 0
            },
            "usage": {
                "max": 7860224,
                "pct": 0.000672283359618831,
                "total": 1409024
            }
        }
    },
    "event": {
        "dataset": "docker.memory",
        "duration": 115000,
        "module": "docker"
    },
    "metricset": {
        "name": "memory"
    },
    "service": {
        "address": "/var/run/docker.sock",
        "type": "docker"
    }
}
```


### Network

The Docker `network` data stream collects network metrics.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| container.id | Unique container id. | keyword |  |
| container.image.name | Name of the image the container was built on. | keyword |  |
| container.name | Container name. | keyword |  |
| container.runtime | Container runtime. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| docker.container.labels.\* | Container labels | object |  |
| docker.network.in.bytes | Total number of incoming bytes. | long | counter |
| docker.network.in.dropped | Total number of dropped incoming packets. | scaled_float | counter |
| docker.network.in.errors | Total errors on incoming packets. | long | counter |
| docker.network.in.packets | Total number of incoming packets. | long | counter |
| docker.network.inbound.bytes | Total number of incoming bytes. | long | counter |
| docker.network.inbound.dropped | Total number of dropped incoming packets. | long | counter |
| docker.network.inbound.errors | Total errors on incoming packets. | long | counter |
| docker.network.inbound.packets | Total number of incoming packets. | long | counter |
| docker.network.interface | Network interface name. | keyword |  |
| docker.network.out.bytes | Total number of outgoing bytes. | long | counter |
| docker.network.out.dropped | Total number of dropped outgoing packets. | scaled_float | counter |
| docker.network.out.errors | Total errors on outgoing packets. | long | counter |
| docker.network.out.packets | Total number of outgoing packets. | long | counter |
| docker.network.outbound.bytes | Total number of outgoing bytes. | long | counter |
| docker.network.outbound.dropped | Total number of dropped outgoing packets. | long | counter |
| docker.network.outbound.errors | Total errors on outgoing packets. | long | counter |
| docker.network.outbound.packets | Total number of outgoing packets. | long | counter |
| ecs.version | ECS version | keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.architecture | Operating system architecture. | keyword |  |
| host.ip | Host ip address. | ip |  |
| host.mac | Host mac address. | keyword |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |
| host.os.full | Operating system name, including the version or code name. | keyword |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |
| host.os.name | Operating system name, without the version. | keyword |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |
| host.os.version | Operating system version as a raw string. | keyword |  |
| host.type | Type of host. | keyword |  |
| service.address | Service address | keyword |  |
| service.type | Service type | keyword |  |


An example event for `network` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "agent": {
        "hostname": "host.example.com",
        "name": "host.example.com"
    },
    "container": {
        "id": "cc78e58acfda4501105dc4de8e3ae218f2da616213e6e3af168c40103829302a",
        "image": {
            "name": "metricbeat_elasticsearch"
        },
        "name": "metricbeat_elasticsearch_1_df866b3a7b3d",
        "runtime": "docker"
    },
    "docker": {
        "container": {
            "labels": {
                "com_docker_compose_config-hash": "e3e0a2c6e5d1afb741bc8b1ecb09cda0395886b7a3e5084a9fd110be46d70f78",
                "com_docker_compose_container-number": "1",
                "com_docker_compose_oneoff": "False",
                "com_docker_compose_project": "metricbeat",
                "com_docker_compose_service": "elasticsearch",
                "com_docker_compose_slug": "df866b3a7b3d50c0802350cbe58ee5b34fa32b7f6ba7fe9e48cde2c12dd0201d",
                "com_docker_compose_version": "1.23.1",
                "license": "Elastic License",
                "org_label-schema_build-date": "20181006",
                "org_label-schema_license": "GPLv2",
                "org_label-schema_name": "elasticsearch",
                "org_label-schema_schema-version": "1.0",
                "org_label-schema_url": "https://www.elastic.co/products/elasticsearch",
                "org_label-schema_vcs-url": "https://github.com/elastic/elasticsearch-docker",
                "org_label-schema_vendor": "Elastic",
                "org_label-schema_version": "6.5.1"
            }
        },
        "network": {
            "in": {
                "bytes": 0,
                "dropped": 0,
                "errors": 0,
                "packets": 0
            },
            "inbound": {
                "bytes": 23047,
                "dropped": 0,
                "errors": 0,
                "packets": 241
            },
            "interface": "eth0",
            "out": {
                "bytes": 0,
                "dropped": 0,
                "errors": 0,
                "packets": 0
            },
            "outbound": {
                "bytes": 0,
                "dropped": 0,
                "errors": 0,
                "packets": 0
            }
        }
    },
    "event": {
        "dataset": "docker.network",
        "duration": 115000,
        "module": "docker"
    },
    "metricset": {
        "name": "network"
    },
    "service": {
        "address": "/var/run/docker.sock",
        "type": "docker"
    }
}
```