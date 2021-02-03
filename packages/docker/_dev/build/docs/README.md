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

{{fields "container"}}

{{event "container"}}

### CPU 

The Docker `cpu` data stream collects runtime CPU metrics.

{{fields "cpu"}}

{{event "cpu"}}

### Diskio

The Docker `diskio` data stream collects disk I/O metrics.

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