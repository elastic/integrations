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
    "@timestamp": "2025-05-30T04:41:15.537Z",
    "agent": {
        "ephemeral_id": "4d61d6ff-d82f-4775-a439-31f8e6da6ae2",
        "id": "fb13f214-2cea-49d6-9de1-ae6c9857ee81",
        "name": "elastic-agent-10784",
        "type": "metricbeat",
        "version": "8.17.0"
    },
    "data_stream": {
        "dataset": "nvidia_gpu.stats",
        "namespace": "20283",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "fb13f214-2cea-49d6-9de1-ae6c9857ee81",
        "snapshot": false,
        "version": "8.17.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "nvidia_gpu.stats",
        "duration": 18298544,
        "ingested": "2025-05-30T04:41:18Z",
        "module": "prometheus"
    },
    "gpu": {
        "clock": {
            "mem_frequency": 405,
            "streaming_multiprocessor_frequency": 300
        },
        "labels": {
            "DCGM_FI_DRIVER_VERSION": "525.105.17",
            "Hostname": "924e17218b6f",
            "UUID": "GPU-2492e3fa-2252-1730-0d1a-8d12ab32cdf0",
            "device": "nvidia0",
            "gpu": "0",
            "instance": "192.168.0.192:9400",
            "job": "prometheus",
            "modelName": "Tesla T4",
            "pci_bus_id": "00000000:00:04.0"
        },
        "license_vgpu_status": 0,
        "memory": {
            "framebuffer": {
                "size": {
                    "free": 14923,
                    "used": 5
                }
            }
        },
        "nvlink": {
            "bandwidth": {
                "total": 0
            }
        },
        "pcie": {
            "replay": 0
        },
        "power": {
            "energy_consumption": {
                "total": 2896518860
            },
            "usage": 11.941
        },
        "temperature": {
            "gpu": 38,
            "memory": 0
        },
        "utilization": {
            "decoder": 0,
            "encoder": 0,
            "gpu": 0,
            "memory_copy": 0
        }
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "elastic-agent-10784",
        "ip": [
            "172.18.0.4",
            "192.168.112.2"
        ],
        "mac": [
            "02-42-AC-12-00-04",
            "02-42-C0-A8-70-02"
        ],
        "name": "elastic-agent-10784",
        "os": {
            "family": "",
            "kernel": "5.15.153.1-microsoft-standard-WSL2",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "metricset": {
        "name": "collector",
        "period": 10000
    },
    "service": {
        "address": "http://192.168.0.192:9400/metrics",
        "type": "prometheus"
    },
    "tags": [
        "preserve_original_event"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| gpu.clock.mem_frequency | Memory clock frequency (in MHz). | float |  | gauge |
| gpu.clock.streaming_multiprocessor_frequency | SM clock frequency (in MHz). | float |  | gauge |
| gpu.dcp.dram.active | Ratio of cycles the device memory interface is active sending or receiving data. | float |  | gauge |
| gpu.dcp.fp16_pipe.active | Ratio of cycles the fp16 pipes are active. | float |  | gauge |
| gpu.dcp.fp32_pipe.active | Ratio of cycles the fp32 pipes are active. | float |  | gauge |
| gpu.dcp.fp64_pipe.active | Ratio of cycles the fp64 pipes are active. | float |  | gauge |
| gpu.dcp.graphics_engine.active | Ratio of time the graphics engine is active. | float |  | gauge |
| gpu.dcp.sm.active | The ratio of cycles an SM has at least one warp assigned. | float |  | gauge |
| gpu.dcp.sm.occupancy | The ratio of number of warps resident on an SM. | float |  | gauge |
| gpu.dcp.tensor_pipe.active | Ratio of cycles the tensor (HMMA) pipe is active. | float |  | gauge |
| gpu.device.brand | Brand of the GPU device. | keyword |  |  |
| gpu.device.ecc_info_rom_version | ECC inforom version | keyword |  |  |
| gpu.device.power_info_rom_version | Power management object inforom version | keyword |  |  |
| gpu.device.serial_number | Device Serial Number | keyword |  |  |
| gpu.ecc.double_bit_persistent | Double-bit persistent errors count for GPU memory. | long |  | counter |
| gpu.ecc.double_bit_volatile | Double-bit volatile errors count for GPU memory. | long |  | counter |
| gpu.ecc.single_bit_persistent | Single-bit persistent errors count for GPU memory. | long |  | counter |
| gpu.ecc.single_bit_volatile | Single-bit volatile errors count for GPU memory. | long |  | counter |
| gpu.error.xid | The eXerience ID of the error being reported by the GPU. | float |  | gauge |
| gpu.labels.\* | Nvidia GPU labels | object |  |  |
| gpu.license_vgpu_status | vGPU License status. | long |  | gauge |
| gpu.memory.framebuffer.size.free | Free size of the framebuffer (in MiB). | float |  | gauge |
| gpu.memory.framebuffer.size.used | Used size of the framebuffer (in MiB). | float |  | gauge |
| gpu.nvlink.bandwidth.total | Total number of NVLink bandwidth counters for all lanes. | long |  | counter |
| gpu.nvlink.bandwidth_l0.total | The number of bytes of active NVLink rx or tx data including both header and payload. | long |  | counter |
| gpu.nvlink.data_crc_errors.count | Total number of NVLink data CRC errors. | long |  | counter |
| gpu.nvlink.flowcontrol_crc_errors.count | Total number of NVLink flow-control CRC errors. | long |  | counter |
| gpu.nvlink.recovery_errors.count | Total number of NVLink recovery errors. | long |  | counter |
| gpu.nvlink.replay_errors.count | Total number of NVLink retries. | long |  | counter |
| gpu.pcie.replay | Replay counter for the PCIe connection. | long |  | counter |
| gpu.pcie.rx_bytes | Total number of bytes received through PCIe RX via NVML. | long | byte | counter |
| gpu.pcie.tx_bytes | Total number of bytes transmitted through PCIe TX via NVML. | long | byte | counter |
| gpu.power.energy_consumption.total | Total energy consumption since boot (in mJ). | long |  | counter |
| gpu.power.usage | Current power usage of the GPU in Watts. | float |  | gauge |
| gpu.remapped.correctable_remapped_rows.count | Number of remapped rows for correctable errors | long |  | counter |
| gpu.remapped.failed_remapped_rows.count | Whether remapping of rows has failed | long |  | gauge |
| gpu.remapped.uncorrectable_remapped_rows.count | Number of remapped rows for uncorrectable errors | long |  | counter |
| gpu.retired.double_bit_errors | Total number of retired pages due to double-bit errors. | long |  | counter |
| gpu.retired.pending | Total number of pages pending retirement. | long |  | counter |
| gpu.retired.single_bit_errors | Total number of retired pages due to single-bit errors. | long |  | counter |
| gpu.temperature.gpu | GPU temperature (in C). | float |  | gauge |
| gpu.temperature.memory | Memory temperature (in C). | float |  | gauge |
| gpu.throttling.board_limit | Number of microseconds throttled due to Board limit. | long |  | counter |
| gpu.throttling.low_utilization | Number of microseconds throttled due to low utilization. | long |  | counter |
| gpu.throttling.power | Number of microseconds throttled due to power. | long |  | counter |
| gpu.throttling.reliability | Number of microseconds throttled due to reliability. | long |  | counter |
| gpu.throttling.sync_boost | Number of microseconds throttled due to Sync Boost. | long |  | counter |
| gpu.throttling.thermal | Number of microseconds throttled due to thermals. | long |  | counter |
| gpu.utilization.decoder | Decoder utilization (in %). | float | percent | gauge |
| gpu.utilization.encoder | Encoder utilization (in %). | float | percent | gauge |
| gpu.utilization.gpu | GPU utilization (in %). | float | percent | gauge |
| gpu.utilization.memory_copy | Memory utilization (in %). | float | percent | gauge |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |
