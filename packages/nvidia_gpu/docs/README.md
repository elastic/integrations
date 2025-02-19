# Nvidia GPU Monitoring

Use the NVIDIA GPU Monitoring integration to monitor the health and performance of your NVIDIA GPUs. The integration collects metrics from the NVIDIA Datacenter GPU Manager and sends them to Elasticsearch.

## Data streams

**stats** give you insight into the state of the NVIDIA GPUs.
Metric data streams collected by the Nvidia GPU Monitoring integration include `stats`. See more details in the [Metrics](#metrics-reference).

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

An example event for `stats` looks as following:

```json
{
    "@timestamp": "2025-02-04T03:58:06.137Z",
    "agent": {
        "ephemeral_id": "33183a42-1f03-4d37-bf77-2a683c47eec1",
        "id": "b6f2a8e1-c701-4a92-a1a2-3a9362ad4af7",
        "name": "4b8c5ec8e940",
        "type": "metricbeat",
        "version": "8.16.1"
    },
    "data_stream": {
        "dataset": "nvidia_gpu.stats",
        "namespace": "default",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "b6f2a8e1-c701-4a92-a1a2-3a9362ad4af7",
        "snapshot": false,
        "version": "8.16.1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "nvidia_gpu.stats",
        "duration": 3729334,
        "ingested": "2025-02-04T03:58:16Z",
        "module": "prometheus"
    },
    "gpu": {
        "decoder": {
            "utilization": 0
        },
        "device": {
            "brand": "GeForce",
            "id": "0",
            "info_rom": {
                "oem_version": "1.1",
                "version": "G001.0000.02.04"
            },
            "model": "NVIDIA GeForce RTX 2060 SUPER",
            "name": "nvidia0",
            "uuid": "GPU-72ca939a-a640-eb0b-df2b-4ac1d7081736",
            "vbios": {
                "version": "90.06.44.00.2f"
            }
        },
        "driver": {
            "nvml_version": "12.560.35.02",
            "version": "560.94"
        },
        "encoder": {
            "utilization": 0
        },
        "energy": {
            "total": 9333403
        },
        "framebuffer": {
            "size": {
                "free": 6990,
                "used": 1015
            }
        },
        "license": {
            "vgpu": "0"
        },
        "memory": {
            "copy_utilization": 10,
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
            "usage": 19.131
        },
        "streaming_multiprocessor": {
            "frequency": 375
        },
        "temperature": 43,
        "utilization": 18
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "4b8c5ec8e940",
        "ip": "172.17.0.3",
        "mac": "02-42-AC-11-00-03",
        "name": "4b8c5ec8e940",
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
            "job": "prometheus",
            "name": "192.168.0.238:9400"
        },
        "up": {
            "value": 0
        }
    },
    "service": {
        "address": "http://192.168.0.238:9400/metrics",
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
