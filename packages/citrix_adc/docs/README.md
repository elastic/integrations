# Citrix ADC Integration

## Overview

The Citrix ADC integration allows you to monitor your Citrix ADC instance. Citrix ADC is an application delivery controller that performs application-specific traffic analysis to intelligently distribute, optimize, and secure Layer 4 - Layer 7 (L4–L7) network traffic for web applications.

Use the Citrix ADC integration to collect metrics related to the system. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference logs when troubleshooting an issue.

## Data streams

The Citrix ADC integration collects metrics data.

Metrics give you insight into the statistics of the Citrix ADC. Metrics data streams collected by the Citrix ADC integration include [system](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/system/system/), so that the user could monitor and troubleshoot the performance of the Citrix ADC instances.

Note:
- Users can monitor and see the metrics inside the ingested documents for Citrix ADC in the logs-* index pattern from `Discover`.

## Compatibility

This integration has been tested against Citrix ADC `v13.0` and `v13.1`.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

In order to ingest data from Citrix ADC, you must know the host(s) and the administrator credentials for the Citrix ADC instance.

Host Configuration Format: `http[s]://host[:port]`

Example Host Configuration: `http://localhost:9080`

### Troubleshooting

There could be a possibility that for some of the fields, Citrix ADC sets dummy values. For example, a field `cpuusagepcnt` is represented by `citrix_adc.system.cpu.utilization.pct`. `cpuusagepcnt` is set to `4294967295` for some [instances](https://github.com/citrix/citrix-adc-metrics-exporter/issues/44). If you also encounter it for some fields please reach out to the [Citrix ADC support team](https://support.citrix.com/plp/products/citrix_adc/tabs/popular-solutions).

## Metrics reference

### System

This is the `system` data stream. With the help of the system endpoint, metrics like memory in use, total system memory, CPU count can be collected along with other statistics for system resources.

An example event for `system` looks as following:

```json
{
    "@timestamp": "2022-11-03T11:58:48.678Z",
    "agent": {
        "ephemeral_id": "17888c67-ea5e-4c24-ad2d-6e1572930f9d",
        "id": "f1fb7954-85ee-4fe3-971d-546763d1571b",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.1"
    },
    "citrix_adc": {
        "system": {
            "cpu": {
                "count": 1,
                "utilization": {
                    "additional_management": {
                        "pct": 0
                    },
                    "avg": {
                        "pct": 4294967300
                    },
                    "management": {
                        "pct": 0.8
                    },
                    "master": {
                        "pct": 4294967300
                    },
                    "packets": {
                        "pct": 1.1
                    },
                    "pct": 1.1,
                    "slave": {
                        "pct": 4294967300
                    }
                }
            },
            "disk": {
                "usage": {
                    "flash_partition": {
                        "pct": 12
                    },
                    "var_partition": {
                        "pct": 12
                    }
                }
            },
            "memory": {
                "size": {
                    "value": 0
                },
                "usage": {
                    "value": 226492416
                },
                "utilization": {
                    "pct": 21.114572
                }
            },
            "start": {
                "time": "2022-09-22T03:50:13.000Z"
            }
        }
    },
    "data_stream": {
        "dataset": "citrix_adc.system",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.4.0"
    },
    "elastic_agent": {
        "id": "f1fb7954-85ee-4fe3-971d-546763d1571b",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "created": "2022-11-03T11:58:48.678Z",
        "dataset": "citrix_adc.system",
        "ingested": "2022-11-03T11:58:52Z",
        "kind": "event",
        "module": "citrix_adc",
        "original": "{\"errorcode\":0,\"message\":\"Done\",\"severity\":\"NONE\",\"system\":{\"addimgmtcpuusagepcnt\":0,\"auxtemp0\":0,\"auxtemp1\":0,\"auxtemp2\":0,\"auxtemp3\":0,\"auxvolt0\":0,\"auxvolt1\":0,\"auxvolt2\":0,\"auxvolt3\":0,\"auxvolt4\":0,\"auxvolt5\":0,\"auxvolt6\":0,\"auxvolt7\":0,\"cpu0temp\":0,\"cpu1temp\":0,\"cpufan0speed\":0,\"cpufan1speed\":0,\"cpuusage\":\"1\",\"cpuusagepcnt\":1.1,\"disk0avail\":1278,\"disk0perusage\":12,\"disk0size\":1585,\"disk0used\":180,\"disk1avail\":11441,\"disk1perusage\":12,\"disk1size\":14179,\"disk1used\":1603,\"fan0speed\":0,\"fan2speed\":0,\"fan3speed\":0,\"fan4speed\":0,\"fan5speed\":0,\"fanspeed\":0,\"internaltemp\":0,\"mastercpuusage\":\"4294967295\",\"memsizemb\":\"0\",\"memusagepcnt\":21.114572,\"memuseinmb\":\"216\",\"mgmtcpu0usagepcnt\":0.8,\"mgmtcpuusagepcnt\":0.8,\"numcpus\":\"1\",\"pktcpuusagepcnt\":1.1,\"powersupply1status\":\"NOT SUPPORTED\",\"powersupply2status\":\"NOT SUPPORTED\",\"powersupply3status\":\"NOT SUPPORTED\",\"powersupply4status\":\"NOT SUPPORTED\",\"rescpuusage\":\"4294967295\",\"rescpuusagepcnt\":4294967295,\"slavecpuusage\":\"4294967295\",\"starttime\":\"Thu Sep 22 03:50:13 2022\",\"starttimelocal\":\"Thu Sep 22 09:20:13 2022\",\"systemfanspeed\":0,\"timesincestart\":\"00:00:00\",\"voltagev12n\":0,\"voltagev12p\":0,\"voltagev33main\":0,\"voltagev33stby\":0,\"voltagev5n\":0,\"voltagev5p\":0,\"voltagev5sb\":0,\"voltagevbat\":0,\"voltagevcc0\":0,\"voltagevcc1\":0,\"voltagevsen2\":0,\"voltagevtt\":0}}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "citrix_adc-system",
        "forwarded"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| citrix_adc.system.cpu.count | The number of CPUs on the NetScaler appliance. | float |  | gauge |
| citrix_adc.system.cpu.utilization.additional_management.pct | Additional Management CPU utilization percentage. | float | percent | gauge |
| citrix_adc.system.cpu.utilization.avg.pct | Shows average CPU utilization percentage if more than 1 CPU is present. | float | percent | gauge |
| citrix_adc.system.cpu.utilization.management.pct | Average Management CPU utilization percentage. | float | percent | gauge |
| citrix_adc.system.cpu.utilization.master.pct | CPU 0 (currently the master CPU) utilization, as percentage of capacity. | float | percent | gauge |
| citrix_adc.system.cpu.utilization.packets.pct | Average CPU utilization percentage for all packet engines excluding management PE. | float | percent | gauge |
| citrix_adc.system.cpu.utilization.pct | CPU utilization percentage. | float | percent | gauge |
| citrix_adc.system.cpu.utilization.slave.pct | CPU 1 (currently the slave CPU) utilization, as percentage of capacity. | float | percent | gauge |
| citrix_adc.system.disk.usage.flash_partition.pct | Used space in /flash partition of the disk, as a percentage. | float | percent | gauge |
| citrix_adc.system.disk.usage.var_partition.pct | Used space in /var partition of the disk, as a percentage. | float | percent | gauge |
| citrix_adc.system.memory.size.value | Total amount of system memory, in bytes. | float | byte | gauge |
| citrix_adc.system.memory.usage.value | Main memory currently in use, in bytes. | float | byte | gauge |
| citrix_adc.system.memory.utilization.pct | Percentage of memory utilization on NetScaler. | float | percent | gauge |
| citrix_adc.system.start.time | Time when the NetScaler appliance was last started. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| error.message | Error message. | match_only_text |  |  |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |  |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |  |  |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |  |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |  |  |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |  |  |
| input.type | Type of Filebeat input. | keyword |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |
