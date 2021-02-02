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
<<metricset-period,`period`>> that is 3 seconds or longer. The request to the
Docker API already takes up to 2 seconds. Specifying less than 3 seconds will
result in requests that timeout, and no data will be reported for those
requests.

## Metrics

### Container

The Docker `container` data stream collects information and statistics about
running Docker containers.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| docker.container.command | Command that was executed in the Docker container. | keyword |
| docker.container.created | Date when the container was created. | date |
| docker.container.ip_addresses | Container IP addresses. | ip |
| docker.container.size.root_fs | Total size of all the files in the container. | long |
| docker.container.size.rw | Size of the files that have been created or changed since creation. | long |
| docker.container.status | Container status. | keyword |
| docker.container.tags | Image tags. | keyword |
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


### CPU 

The Docker `cpu` data stream collects runtime CPU metrics.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| docker.cpu.core.*.norm.pct | Percentage of CPU time in this core, normalized by the number of CPU cores. | object |
| docker.cpu.core.*.pct | Percentage of CPU time in this core. | object |
| docker.cpu.core.*.ticks | Number of CPU ticks in this core. | object |
| docker.cpu.kernel.norm.pct | Percentage of time in kernel space normalized by the number of CPU cores. | scaled_float |
| docker.cpu.kernel.pct | Percentage of time in kernel space. | scaled_float |
| docker.cpu.kernel.ticks | CPU ticks in kernel space. | long |
| docker.cpu.system.norm.pct | Percentage of total CPU time in the system normalized by the number of CPU cores. | scaled_float |
| docker.cpu.system.pct | Percentage of total CPU time in the system. | scaled_float |
| docker.cpu.system.ticks | CPU system ticks. | long |
| docker.cpu.total.norm.pct | Total CPU usage normalized by the number of CPU cores. | scaled_float |
| docker.cpu.total.pct | Total CPU usage. | scaled_float |
| docker.cpu.user.norm.pct | Percentage of time in user space normalized by the number of CPU cores. | scaled_float |
| docker.cpu.user.pct | Percentage of time in user space. | scaled_float |
| docker.cpu.user.ticks | CPU ticks in user space. | long |
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


### Diskio

The Docker `diskio` data stream collects disk I/O metrics.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| docker.diskio.read.bytes | Bytes read during the life of the container | long |
| docker.diskio.read.ops | Number of reads during the life of the container | long |
| docker.diskio.read.queued | Total number of queued requests | long |
| docker.diskio.read.rate | Number of current reads per second | long |
| docker.diskio.read.service_time | Total time to service IO requests, in nanoseconds | long |
| docker.diskio.read.wait_time | Total time requests spent waiting in queues for service, in nanoseconds | long |
| docker.diskio.reads | Number of current reads per second | scaled_float |
| docker.diskio.summary.bytes | Bytes read and written during the life of the container | long |
| docker.diskio.summary.ops | Number of I/O operations during the life of the container | long |
| docker.diskio.summary.queued | Total number of queued requests | long |
| docker.diskio.summary.rate | Number of current operations per second | long |
| docker.diskio.summary.service_time | Total time to service IO requests, in nanoseconds | long |
| docker.diskio.summary.wait_time | Total time requests spent waiting in queues for service, in nanoseconds | long |
| docker.diskio.total | Number of reads and writes per second | scaled_float |
| docker.diskio.write.bytes | Bytes written during the life of the container | long |
| docker.diskio.write.ops | Number of writes during the life of the container | long |
| docker.diskio.write.queued | Total number of queued requests | long |
| docker.diskio.write.rate | Number of current writes per second | long |
| docker.diskio.write.service_time | Total time to service IO requests, in nanoseconds | long |
| docker.diskio.write.wait_time | Total time requests spent waiting in queues for service, in nanoseconds | long |
| docker.diskio.writes | Number of current writes per second | scaled_float |
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


### Event

The Docker `event` data stream collects docker events

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| docker.event.action | The type of event | keyword |
| docker.event.actor.attributes | Various key/value attributes of the object, depending on its type | object |
| docker.event.actor.id | The ID of the object emitting the event | keyword |
| docker.event.from | Event source | keyword |
| docker.event.id | Event id when available | keyword |
| docker.event.status | Event status | keyword |
| docker.event.type | The type of object emitting the event | keyword |
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


### Healthcheck

The Docker `healthcheck` data stream collects healthcheck status metrics about
running Docker containers.

Healthcheck data will only be available from docker containers where the
docker `HEALTHCHECK` instruction has been used to build the docker image.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| docker.healthcheck.event.end_date | Healthcheck end date | date |
| docker.healthcheck.event.exit_code | Healthcheck status code | integer |
| docker.healthcheck.event.output | Healthcheck output | keyword |
| docker.healthcheck.event.start_date | Healthcheck start date | date |
| docker.healthcheck.failingstreak | concurent failed check | integer |
| docker.healthcheck.status | Healthcheck status code | keyword |
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


### Image

The Docker `image` data stream collects metrics on docker images

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| docker.image.created | Date and time when the image was created. | date |
| docker.image.id.current | Unique image identifier given upon its creation. | keyword |
| docker.image.id.parent | Identifier of the image, if it exists, from which the current image directly descends. | keyword |
| docker.image.labels | Image labels. | object |
| docker.image.size.regular | Total size of the all cached images associated to the current image. | long |
| docker.image.size.virtual | Size of the image. | long |
| docker.image.tags | Image tags. | keyword |
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


### Info 

The Docker `info` data stream collects system-wide information based on the
https://docs.docker.com/engine/reference/api/docker_remote_api_v1.24/#/display-system-wide-information[Docker Remote API].

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| docker.info.containers.paused | Total number of paused containers. | long |
| docker.info.containers.running | Total number of running containers. | long |
| docker.info.containers.stopped | Total number of stopped containers. | long |
| docker.info.containers.total | Total number of existing containers. | long |
| docker.info.id | Unique Docker host identifier. | keyword |
| docker.info.images | Total number of existing images. | long |
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


### Memory

The Docker `memory` data stream collects memory metrics from docker.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| docker.memory.commit.peak | Peak committed bytes on Windows | long |
| docker.memory.commit.total | Total bytes | long |
| docker.memory.fail.count | Fail counter. | scaled_float |
| docker.memory.limit | Memory limit. | long |
| docker.memory.private_working_set.total | private working sets on Windows | long |
| docker.memory.rss.pct | Memory resident set size percentage. | scaled_float |
| docker.memory.rss.total | Total memory resident set size. | long |
| docker.memory.stats.* | Raw memory stats from the cgroups memory.stat interface | object |
| docker.memory.usage.max | Max memory usage. | long |
| docker.memory.usage.pct | Memory usage percentage. | scaled_float |
| docker.memory.usage.total | Total memory usage. | long |
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



### Network

The Docker `network` data stream collects network metrics.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| docker.network.in.bytes | Total number of incoming bytes. | long |
| docker.network.in.dropped | Total number of dropped incoming packets. | scaled_float |
| docker.network.in.errors | Total errors on incoming packets. | long |
| docker.network.in.packets | Total number of incoming packets. | long |
| docker.network.inbound.bytes | Total number of incoming bytes. | long |
| docker.network.inbound.dropped | Total number of dropped incoming packets. | long |
| docker.network.inbound.errors | Total errors on incoming packets. | long |
| docker.network.inbound.packets | Total number of incoming packets. | long |
| docker.network.interface | Network interface name. | keyword |
| docker.network.out.bytes | Total number of outgoing bytes. | long |
| docker.network.out.dropped | Total number of dropped outgoing packets. | scaled_float |
| docker.network.out.errors | Total errors on outgoing packets. | long |
| docker.network.out.packets | Total number of outgoing packets. | long |
| docker.network.outbound.bytes | Total number of outgoing bytes. | long |
| docker.network.outbound.dropped | Total number of dropped outgoing packets. | long |
| docker.network.outbound.errors | Total errors on outgoing packets. | long |
| docker.network.outbound.packets | Total number of outgoing packets. | long |
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
