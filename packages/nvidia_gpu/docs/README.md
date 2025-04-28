# Nvidia GPU Monitoring

Use the NVIDIA GPU Monitoring integration to monitor the health and performance of your NVIDIA GPUs. The integration collects metrics from the NVIDIA Datacenter GPU Manager and sends them to Elasticsearch.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

You need the NVIDIA Datacenter GPU Manager (DCGM) installed on your system (or exposed via a docker container with the GPU device mounted) to collect metrics from the NVIDIA GPUs. You can download the DCGM from the [NVIDIA website](https://developer.nvidia.com/dcgm). By default the DCGM exporter does not expose all available metrics, to customize the list of available metrics, a csv file with the desired metrics is required. For instructions on how to do this, review the dcgm-exporter documentation.

If DCGM Exporter is configured to provide enrichment of Kubernetes data, the pod, namespace, and container information will be attached to the corresponding metrics. This is useful for monitoring and attributing GPU usage in Kubernetes environments.

This integration has been tested with version 3.3.9 of the DCGM exporter.

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

When running on Kubernetes, you can use ${env.NODE_NAME} to get the node name for use in the hosts field. For example: `hosts: http://${env.NODE_NAME}:9400/metrics`.

### Customizing the list of available metrics

With `dcgm-exporter` you can configure which fields are collected by specifying a custom CSV file.
You will find the default CSV file under `etc/default-counters.csv` in the repository, which is copied on your system or container to `/etc/dcgm-exporter/default-counters.csv`

The layout and format of this file is as follows:

```
# Format
# If line starts with a '#' it is considered a comment
# DCGM FIELD, Prometheus metric type, help message

# Clocks
DCGM_FI_DEV_SM_CLOCK,  gauge, SM clock frequency (in MHz).
DCGM_FI_DEV_MEM_CLOCK, gauge, Memory clock frequency (in MHz).
```

A custom csv file can be specified using the `-f` option or `--collectors` as follows:

```shell
dcgm-exporter -f /tmp/custom-collectors.csv
```

See more in the [DCGM Github Repository](https://github.com/NVIDIA/dcgm-exporter/tree/main)

## Data streams

**stats** give you insight into the state of the NVIDIA GPUs.
Metric data streams collected by the Nvidia GPU Monitoring integration include `stats`. See more details in the [Metrics](#metrics-reference).

An example event for `stats` looks as following:

```json
{
    "@timestamp": "2025-04-15T15:31:41.513Z",
    "agent": {
        "ephemeral_id": "398cee14-e976-4ee0-ae74-df923b06e08f",
        "id": "60465982-823e-4f9d-b330-4bebc7e0b4aa",
        "name": "093b05dfeffc",
        "type": "metricbeat",
        "version": "8.16.6"
    },
    "data_stream": {
        "dataset": "nvidia_gpu.stats",
        "namespace": "default",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "60465982-823e-4f9d-b330-4bebc7e0b4aa",
        "snapshot": false,
        "version": "8.16.6"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "nvidia_gpu.stats",
        "duration": 14458458,
        "ingested": "2025-04-15T15:31:51Z",
        "module": "prometheus"
    },
    "gpu": {
        "decoder": {
            "utilization": 2
        },
        "device": {
            "id": "0",
            "model": "NVIDIA GeForce RTX 2060 SUPER",
            "name": "nvidia0",
            "uuid": "GPU-72ca939a-a640-eb0b-df2b-4ac1d7081736"
        },
        "driver": {
            "version": "560.94"
        },
        "encoder": {
            "utilization": 0
        },
        "energy": {
            "total": 68062938297
        },
        "framebuffer": {
            "size": {
                "free": 247,
                "used": 7758
            }
        },
        "license": {
            "vgpu": "0"
        },
        "memory": {
            "copy_utilization": 13,
            "frequency": 405,
            "temperature": 0
        },
        "nvlink": {
            "bandwidth": {
                "total": 0
            }
        },
        "pci": {
            "bus": {
                "id": "00000000:01:00.0"
            }
        },
        "power": {
            "usage": 21.382
        },
        "streaming_multiprocessor": {
            "frequency": 300
        },
        "temperature": 44,
        "utilization": 12
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "093b05dfeffc",
        "ip": [
            "172.17.0.3"
        ],
        "mac": [
            "02-42-AC-11-00-03"
        ],
        "name": "093b05dfeffc",
        "os": {
            "codename": "noble",
            "family": "debian",
            "kernel": "6.10.14-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "24.04.1 LTS (Noble Numbat)"
        }
    },
    "metricset": {
        "name": "collector",
        "period": 10000
    },
    "prometheus": {
        "node": {
            "hostname": "de4a75bd4194",
            "job": "prometheus"
        }
    },
    "server": {
        "address": "192.168.0.192:9400"
    },
    "service": {
        "address": "http://192.168.0.192:9400/metrics",
        "type": "prometheus"
    }
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| gpu.decoder.utilization | Utilization of the decoder engine in the GPU. | float | gauge |
| gpu.device.brand | Brand of the GPU device. | keyword |  |
| gpu.device.id | ID of the GPU device. | keyword |  |
| gpu.device.info_rom.oem_version | OEM version of the info ROM. | keyword |  |
| gpu.device.info_rom.version | Version of the info ROM. | keyword |  |
| gpu.device.model | Model of the GPU device. | keyword |  |
| gpu.device.name | Name of the GPU device. | keyword |  |
| gpu.device.uuid | UUID of the GPU device. | keyword |  |
| gpu.device.vbios.version | Version of the vbios. | keyword |  |
| gpu.driver.nvml_version | NVML version of the driver. | keyword |  |
| gpu.driver.version | Version of the driver. | keyword |  |
| gpu.encoder.utilization | Utilization of the encoder engine in the GPU. | float |  |
| gpu.energy.total | Total energy consumption of the GPU since boot in Joules. | long | counter |
| gpu.error.code | Specific Error code for the XID error on the GPU. | keyword |  |
| gpu.error.message | Specific Error message for the XID error on the. | keyword |  |
| gpu.error.xid | The eXerience ID of the error being reported by the GPU. | keyword |  |
| gpu.framebuffer.size.free | Free size of the framebuffer. | long | gauge |
| gpu.framebuffer.size.used | Used size of the framebuffer. | long | gauge |
| gpu.license.vgpu | License status related to vGPU. | keyword |  |
| gpu.memory.copy_utilization | Utilization of the GPU memory copy engine. | float | gauge |
| gpu.memory.errors.double_bit_persistent | Double-bit persistent errors count for GPU memory. | long | gauge |
| gpu.memory.errors.double_bit_volatile | Double-bit volatile errors count for GPU memory. | long | gauge |
| gpu.memory.errors.single_bit_persistent | Single-bit persistent errors count for GPU memory. | long | gauge |
| gpu.memory.errors.single_bit_volatile | Single-bit volatile errors count for GPU memory. | long | gauge |
| gpu.memory.frequency | Clock frequency of the GPU memory. | float | gauge |
| gpu.memory.size | Size of the GPU memory in MB. | long | gauge |
| gpu.memory.temperature | Temperature of the GPU memory. | float | gauge |
| gpu.memory.used | Used size of the GPU memory in MB. | long | gauge |
| gpu.nvlink.bandwidth.total | Total bandwidth of NVLink. | long | gauge |
| gpu.pci.bus.id | Bus ID of the PCI device. | keyword |  |
| gpu.pcie.replay | Replay counter for the PCIe connection. | long | gauge |
| gpu.power.usage | Current power usage of the GPU in Watts. | float | gauge |
| gpu.streaming_multiprocessor.frequency | Frequency of the streaming multiprocessor. | float | gauge |
| gpu.temperature | Temperature of the GPU. | float | gauge |
| gpu.throttling.board_limit | Number of microseconds throttled due to Board limit. | float | gauge |
| gpu.throttling.low_utilization | Number of microseconds throttled due to low utilization. | float | gauge |
| gpu.throttling.power | Number of microseconds throttled due to power. | float | gauge |
| gpu.throttling.reliability | Number of microseconds throttled due to reliability. | float | gauge |
| gpu.throttling.sync_boost | Number of microseconds throttled due to Sync Boost. | float | gauge |
| gpu.throttling.thermal | Number of microseconds throttled due to thermals. | float | gauge |
| gpu.utilization | Overall utilization of the GPU. | float | gauge |
| kubernetes.container.name | Kubernetes container name | keyword |  |
| kubernetes.namespace | Kubernetes namespace | keyword |  |
| kubernetes.pod.name | Kubernetes pod name | keyword |  |
| prometheus.node.hostname | Hostname of the Prometheus node. | keyword |  |
| prometheus.node.id | ID of the Prometheus node. | integer |  |
| prometheus.node.job | Job of the Prometheus node. | keyword |  |
| prometheus.up.value | Whether prometheus reports the targeted instance as up or down. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |
