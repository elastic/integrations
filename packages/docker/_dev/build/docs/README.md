# Docker Integration

This Integration collects metrics and logs from [Docker](https://www.docker.com/) containers. 
The default data streams for metrics collection are: `container`, `cpu`, `diskio`, `healthcheck`, `info`, `memory`
and `network`. The `image` metricset is not enabled by default.
The `container_logs` data stream for containers' logs collection is enabled by default.

## Compatibility

The Docker integration is currently tested on Linux and Mac with the community edition engine, versions 1.11 and 17.09.0-ce.

The Docker integration supports collection of metrics from Podman’s Docker-compatible API by Elastic Agent 8.16.2 or later versions. It has been tested on Linux and Mac with Podman Rest API v2.0.0 and above.

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

For log collection since the discovery of the containers happen automatically, again access to `unix:///var/run/docker.sock`
will be needed so as Agent to be able to watch for Container events.
In addition, access is required to the containers' logs files which by default follows the pattern of
`/var/lib/docker/containers/${docker.container.id}/*-json.log`
If Elastic Agent is running inside docker, you'll need to mount the logs' directory too inside the container:


```
docker run -d \
  --name=metricbeat \
  --user=root \
  --volume="/var/run/docker.sock:/var/run/docker.sock:ro" \
  --volume="/var/lib/docker/containers:/var/lib/docker/containers:ro" \
  docker.elastic.co/beats/metricbeat:latest metricbeat -e \
  -E output.elasticsearch.hosts=["elasticsearch:9200"]
```

In all cases make sure that Agent has the proper permissions to access these files.

## Module-specific configuration notes

It is strongly recommended that you run Docker metricsets with a
{{ url "metricbeat-configuration-metricset-period" "`period`" }}
that is 3 seconds or longer. The request to the
Docker API already takes up to 2 seconds. Specifying less than 3 seconds will
result in requests that timeout, and no data will be reported for those
requests.

In the case of Podman, the configuration parameter podman should be switched to true. This enables streaming of container stats output, which allows for more accurate CPU percentage calculations when using Podman.

## Metrics

### Container

The Docker `container` data stream collects information and statistics about
running Docker containers.

{{fields "container"}}

{{event "container"}}

### CPU

The Docker `cpu` data stream collects runtime CPU metrics.

{{fields "cpu"}}

{{event "cpu"}}

### Diskio

The Docker `diskio` data stream collects disk I/O metrics.

#### Some diskio fields may report zero values

When collecting container disk I/O metrics, some fields may consistently report zero values. This is a known behavior caused by limitations in Docker's stats API and the underlying Linux cgroups subsystem — not a bug in the integration. This also applies to stats collected from Podman.

**Docker API limitations:** Fields such as `docker.diskio.read.service_time`, `docker.diskio.read.wait_time`, and `docker.diskio.read.queued` are always zero because Docker's stats API does not populate the underlying values (these fields are returned as empty arrays).

**cgroups version differences:**
- **cgroups v1** provides more detailed block I/O statistics. Fields like `docker.diskio.read.ops` and `docker.diskio.write.ops` are typically populated.
- **cgroups v2** exposes fewer block I/O metrics through the Docker API. Most fields beyond basic read/write bytes remain zero, including ops, queued, service_time, and wait_time.

**What remains available:** `docker.diskio.read.bytes`, `docker.diskio.write.bytes`, `docker.diskio.read.ops`, and `docker.diskio.write.ops` are the primary indicators of I/O activity and remain available regardless of cgroups version.

**Recommendation:** To get a more complete picture of disk I/O, complement container-level metrics with the [System integration's](https://docs.elastic.co/integrations/system) `system.diskio.*` metrics (collected from `/proc/diskstats`), which are cgroup-version-independent and provide fields such as `io_time`, `iops_in_progress`, `read.time`, and `write.time`.

{{fields "diskio"}}

{{event "diskio"}}

### Event

The Docker `event` data stream collects docker events

{{fields "event"}}

{{event "event"}}

### Healthcheck

The Docker `healthcheck` data stream collects healthcheck status metrics about
running Docker containers.

Healthcheck data will only be available from docker containers where the
docker `HEALTHCHECK` instruction has been used to build the docker image.

{{fields "healthcheck"}}

{{event "healthcheck"}}

### Image

The Docker `image` data stream collects metrics on docker images

{{fields "image"}}

{{event "image"}}

### Info

The Docker `info` data stream collects system-wide information based on the
https://docs.docker.com/engine/reference/api/docker_remote_api_v1.24/#/display-system-wide-information[Docker Remote API].

{{fields "info"}}

{{event "info"}}

### Memory

The Docker `memory` data stream collects memory metrics from docker.

{{fields "memory"}}

{{event "memory"}}


### Network

The Docker `network` data stream collects network metrics.

{{fields "network"}}

{{event "network"}}

### container_logs

The Docker `container_logs` data stream collects container logs.

{{fields "container_logs"}}

{{event "container_logs"}}