# GoFlow2

The GoFlow2 integration allows you to monitor goflow2 logs.

Supported logs
 - sflow
    - At the moment only a limited number of goflow2 fields are fully supported.
 

## Data streams

The Goflow2 sFlow integration collects one type of data streams: logs

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

You need GoFlow2 to create log files for sFlow traffic.
https://github.com/netsampler/goflow2

## Setup

- Install integration and role out elastic agent
- Install GoFlow2 for sFlow logging

Please use the following GoFlow2 mapping.yaml file:

```
# File: mapping.yaml
formatter:
    fields: # list of fields to format in JSON
        - type
        - time_flow_start_ns
        - sampler_address
        - sequence_num
        - in_if
        - out_if
        - src_addr
        - dst_addr
        - etype
        - proto
        - src_port
        - dst_port
        - src_vlan
        - dst_vlan
        - ip_flags
        - sampling_rate
        - bytes
```

The output sflow transport files must be stored in the directory ```/var/log/sflow/goflow2/```

Full command to run GoFlow2 for sflow traffic:
```shell
goflow2 -format json -listen "sflow://:6343" -mapping /root/sflow/goflow2/mapping.yaml -transport.file /var/log/sflow/goflow2/goflow2.log
```