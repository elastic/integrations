# Juniper JunOS Metrics Integration

This integration collects operational metrics and alarm logs from Juniper JunOS devices via the REST API. It uses CEL input to poll RPC endpoints and produces TSDB-compatible time series data across 13 data streams covering device health, network protocols, hardware environment, and inventory.

## Compatibility

Tested with JunOS 21.x and later. Requires the JunOS REST API to be enabled.

## Setup

### JunOS REST API configuration

From JunOS configuration mode, create a read-only user and enable the REST API:

```
# Read-only login class — 'view' is the minimum permission required
set system login class elastic-monitor permissions view
set system login class elastic-monitor deny-commands "configure|edit|set|delete|rollback|commit|request|start|restart|clear|file"

# Service account
set system login user elastic-agent class elastic-monitor
set system login user elastic-agent authentication plain-text-password

# Enable REST API (HTTP or HTTPS)
set system services rest http port 8080
# set system services rest https port 3443
# set system services rest https default-certificate

# Optional: restrict access to the Elastic Agent host
set system services rest control allowed-sources 10.0.0.50/32

commit
```

The `view` permission grants read-only access to all operational RPCs. No `configure`, `edit`, or `request` permissions are needed. Prefer HTTPS and use `allowed-sources` to limit exposure.

This integration calls the following RPC endpoints:

| RPC | Data stream |
|-----|-------------|
| `get-route-engine-information` | `juniper_junos_metrics.route_engine` |
| `get-interface-information` | `juniper_junos_metrics.interfaces`, `juniper_junos_metrics.interface_queues` |
| `get-bgp-summary-information` | `juniper_junos_metrics.bgp` |
| `get-ospf-overview-information` | `juniper_junos_metrics.ospf` |
| `get-route-summary-information` | `juniper_junos_metrics.routing_table` |
| `get-system-storage` | `juniper_junos_metrics.storage` |
| `get-environment-information` | `juniper_junos_metrics.environment` |
| `get-system-alarm-information` | `juniper_junos_metrics.alarm` |
| `get-arp-table-information` | `juniper_junos_metrics.arp` |
| `get-lldp-neighbors-information` | `juniper_junos_metrics.lldp` |
| `get-system-users-information` | `juniper_junos_metrics.system` |
| `get-system-information` | `juniper_junos_metrics.system_info` |

### Known limitations

On dual routing engine systems, automatic hostname detection does not unwrap the `multi-routing-engine-results` envelope returned by the REST API. If the **Device Name** field is left blank, `observer.name` will fall back to the configured host IP instead of the device hostname. Set the **Device Name** field explicitly to avoid this.

### Elastic Agent configuration

1. In Kibana, go to **Integrations** and search for "Juniper JunOS Metrics".
2. Add the integration and set the device host, port, username, and password.
3. Enable **Use HTTPS** if the device serves the REST API over TLS.
4. Set SSL verification mode to `none` for self-signed certificates, or `full` for trusted certificates.
5. Deploy the policy to an Elastic Agent with network access to the device.

## Data Streams

### Route Engine

The `route_engine` data stream collects per-slot route engine metrics including CPU utilization, memory buffer usage, temperature, load averages, and uptime. Each polling interval produces one event per route engine slot. OTel-aligned `system.cpu.utilization` and `system.memory.utilization` fields are computed from the native JunOS values.

An example event for `route_engine` looks as following:

```json
{
    "event": {
        "dataset": "juniper_junos_metrics.route_engine",
        "kind": "metric",
        "module": "juniper_junos_metrics"
    },
    "host": {
        "uptime": 11690
    },
    "juniper": {
        "junos": {
            "route_engine": {
                "cpu": {
                    "background": 0.0,
                    "idle": 89.0,
                    "interrupt": 0.0,
                    "kernel": 5.0,
                    "user": 6.0
                },
                "last_reboot_reason": "Router rebooted after a normal shutdown.",
                "load_average": {
                    "fifteen_minute": 0.58,
                    "five_minute": 0.47,
                    "one_minute": 0.49
                },
                "mastership_state": "master",
                "memory": {
                    "buffer_utilization": 19.0,
                    "total": 1920991232
                },
                "model": "RE-VMX",
                "slot": "0",
                "start_time": "2026-03-10T07:40:35Z",
                "status": "OK",
                "uptime": 11690
            }
        }
    },
    "observer": {
        "product": "JunOS",
        "type": "router",
        "vendor": "Juniper"
    },
    "system": {
        "cpu": {
            "utilization": 0.11
        },
        "memory": {
            "utilization": 0.19
        }
    },
    "data_stream": {
        "type": "metrics",
        "dataset": "juniper_junos_metrics.route_engine",
        "namespace": "default"
    },
    "ecs": {
        "version": "8.0.0"
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. | keyword |  |  |
| error.message | Error message. | match_only_text |  |  |
| event.category | Event category for ECS compatibility. | keyword |  |  |
| event.dataset | Event dataset. | constant_keyword |  |  |
| event.kind | The kind of event. | keyword |  |  |
| event.module | Event module. | constant_keyword |  |  |
| event.type | Event type for ECS compatibility. | keyword |  |  |
| host.uptime | Device uptime in seconds. | long |  | gauge |
| juniper.junos.route_engine.cpu.background | Percentage of CPU time spent on background (nice) processes. | float | percent | gauge |
| juniper.junos.route_engine.cpu.idle | Percentage of CPU time spent idle with no pending work. | float | percent | gauge |
| juniper.junos.route_engine.cpu.interrupt | Percentage of CPU time spent servicing hardware interrupts. | float | percent | gauge |
| juniper.junos.route_engine.cpu.kernel | Percentage of CPU time spent in kernel space. | float | percent | gauge |
| juniper.junos.route_engine.cpu.user | Percentage of CPU time spent executing user-space processes. | float | percent | gauge |
| juniper.junos.route_engine.cpu_cores.background | Per-core background CPU utilization. | float | percent | gauge |
| juniper.junos.route_engine.cpu_cores.id | CPU core ID. | integer |  |  |
| juniper.junos.route_engine.cpu_cores.idle | Per-core idle CPU percentage. | float | percent | gauge |
| juniper.junos.route_engine.cpu_cores.interrupt | Per-core interrupt CPU utilization. | float | percent | gauge |
| juniper.junos.route_engine.cpu_cores.kernel | Per-core kernel CPU utilization. | float | percent | gauge |
| juniper.junos.route_engine.cpu_cores.user | Per-core user CPU utilization. | float | percent | gauge |
| juniper.junos.route_engine.last_reboot_reason | Reported reason for the most recent route engine reboot. | keyword |  |  |
| juniper.junos.route_engine.load_average.fifteen_minute | System load average over the last 15 minutes. | float |  | gauge |
| juniper.junos.route_engine.load_average.five_minute | System load average over the last 5 minutes. | float |  | gauge |
| juniper.junos.route_engine.load_average.one_minute | System load average over the last 1 minute. | float |  | gauge |
| juniper.junos.route_engine.mastership_state | Redundancy role of the route engine, either master or backup. | keyword |  |  |
| juniper.junos.route_engine.memory.buffer_utilization | Percentage of route engine memory currently in use by buffers and caches. | float | percent | gauge |
| juniper.junos.route_engine.memory.installed | Total installed memory in bytes (from memory-installed-size). | long | byte | gauge |
| juniper.junos.route_engine.memory.total | Total installed memory available to the route engine in bytes. | long | byte | gauge |
| juniper.junos.route_engine.model | Route engine hardware model string. | keyword |  |  |
| juniper.junos.route_engine.serial_number | Hardware serial number of the route engine. | keyword |  |  |
| juniper.junos.route_engine.slot | Route engine slot identifier. Used as a TSDB dimension. | keyword |  |  |
| juniper.junos.route_engine.start_time | Timestamp when the route engine was last started. | date |  |  |
| juniper.junos.route_engine.status | Operational status of the route engine (for example OK, Testing, Failed). | keyword |  |  |
| juniper.junos.route_engine.temperature.cpu | Current CPU die temperature in degrees Celsius. | float |  | gauge |
| juniper.junos.route_engine.temperature.routing_engine | Current route engine board temperature in degrees Celsius. | float |  | gauge |
| juniper.junos.route_engine.uptime | Route engine uptime in seconds, measured from the most recent start. | long | s | gauge |
| juniper.junos.route_engine.uptime_days | Route engine uptime in days, measured from the most recent start. Pre-computed from uptime seconds for dashboard display. | float |  | gauge |
| observer.name | Device address configured for this integration instance, used as a TSDB dimension to distinguish devices. | keyword |  |  |
| observer.product | Observer product name. | keyword |  |  |
| observer.type | Observer type such as router, switch, or firewall. | keyword |  |  |
| observer.vendor | Observer vendor name. | keyword |  |  |
| system.cpu.utilization | CPU utilization as a fraction from 0 to 1, derived from (1 - cpu.idle / 100). | float |  | gauge |
| system.memory.utilization | Memory utilization as a fraction from 0 to 1, derived from memory.buffer_utilization / 100. | float |  | gauge |


### Interfaces

The `interfaces` data stream collects per-interface traffic and error metrics. Each polling interval produces one event per physical interface. Fields include byte and packet counters, rate gauges, error counts, and drop counts. OTel-aligned `system.network.*` fields aggregate the per-direction counters.

An example event for `interfaces` looks as following:

```json
{
    "event": {
        "dataset": "juniper_junos_metrics.interfaces",
        "kind": "metric",
        "module": "juniper_junos_metrics"
    },
    "juniper": {
        "junos": {
            "interfaces": {
                "admin_status": "up",
                "link_type": "Full-Duplex",
                "mac_address": "52:54:00:12:bd:fe",
                "mtu": 1514,
                "name": "em1",
                "oper_status": "up",
                "snmp_index": 23,
                "speed": "10Gbps",
                "traffic": {
                    "input": {
                        "packets": 90573
                    },
                    "output": {
                        "packets": 123407
                    }
                },
                "type": "Ethernet"
            }
        }
    },
    "observer": {
        "product": "JunOS",
        "type": "router",
        "vendor": "Juniper"
    },
    "data_stream": {
        "type": "metrics",
        "dataset": "juniper_junos_metrics.interfaces",
        "namespace": "default"
    },
    "ecs": {
        "version": "8.0.0"
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. | keyword |  |  |
| error.message | Error message. | match_only_text |  |  |
| event.category | Event category for ECS compatibility. | keyword |  |  |
| event.dataset | Event dataset. | constant_keyword |  |  |
| event.kind | The kind of event. | keyword |  |  |
| event.module | Event module. | constant_keyword |  |  |
| event.type | Event type for ECS compatibility. | keyword |  |  |
| juniper.junos.interfaces.admin_status | Administrative status of the interface (up or down), reflecting the configured state. | keyword |  |  |
| juniper.junos.interfaces.auto_negotiation | Auto-negotiation state of the interface (enabled or turned off). | keyword |  |  |
| juniper.junos.interfaces.description | Operator-configured description string for the interface. | keyword |  |  |
| juniper.junos.interfaces.errors.aged_packets | Cumulative number of packets dropped because they aged out in the output queue. | long |  | counter |
| juniper.junos.interfaces.errors.carrier_transitions | Number of times the carrier signal changed state (link up/down transitions). | long |  | counter |
| juniper.junos.interfaces.errors.framing_errors | Cumulative number of frames received with alignment or synchronization errors. | long |  | counter |
| juniper.junos.interfaces.errors.hs_link_crc_errors | Cumulative number of high-speed link CRC errors on the fabric side. | long |  | counter |
| juniper.junos.interfaces.errors.input | Cumulative number of inbound packets that contained errors (for example CRC, framing). | long |  | counter |
| juniper.junos.interfaces.errors.input_discards | Cumulative number of inbound packets discarded due to resource exhaustion. | long |  | counter |
| juniper.junos.interfaces.errors.input_drops | Cumulative number of inbound packets dropped due to resource constraints or policy. | long |  | counter |
| juniper.junos.interfaces.errors.input_fifo_errors | Cumulative number of input FIFO overrun errors. | long |  | counter |
| juniper.junos.interfaces.errors.input_giants | Cumulative number of oversized frames received (larger than maximum frame size). | long |  | counter |
| juniper.junos.interfaces.errors.input_l2_channel_errors | Cumulative number of Layer 2 channel mismatch errors. | long |  | counter |
| juniper.junos.interfaces.errors.input_l2_mismatch_timeouts | Cumulative number of Layer 2 mismatch timeout errors. | long |  | counter |
| juniper.junos.interfaces.errors.input_l3_incompletes | Cumulative number of packets with incomplete Layer 3 headers. | long |  | counter |
| juniper.junos.interfaces.errors.input_resource_errors | Cumulative number of input resource exhaustion errors. | long |  | counter |
| juniper.junos.interfaces.errors.input_runts | Cumulative number of undersized frames received (smaller than minimum frame size). | long |  | counter |
| juniper.junos.interfaces.errors.mtu_errors | Cumulative number of packets dropped due to MTU violations. | long |  | counter |
| juniper.junos.interfaces.errors.output | Cumulative number of outbound packets that failed to transmit due to errors. | long |  | counter |
| juniper.junos.interfaces.errors.output_collisions | Cumulative number of Ethernet collisions on the interface. | long |  | counter |
| juniper.junos.interfaces.errors.output_drops | Cumulative number of outbound packets dropped due to queue overflow or policy. | long |  | counter |
| juniper.junos.interfaces.errors.output_fifo_errors | Cumulative number of output FIFO overrun errors. | long |  | counter |
| juniper.junos.interfaces.errors.output_resource_errors | Cumulative number of output resource exhaustion errors. | long |  | counter |
| juniper.junos.interfaces.flap_seconds | Seconds elapsed after the most recent interface flap (from junos:seconds attribute). | long | s | gauge |
| juniper.junos.interfaces.flow_control | Flow control state of the interface (enabled or turned off). | keyword |  |  |
| juniper.junos.interfaces.generation | Interface configuration generation number. | long |  |  |
| juniper.junos.interfaces.last_flapped | Human-readable timestamp of last interface flap. | keyword |  |  |
| juniper.junos.interfaces.link_type | Physical link mode (for example Full-Duplex, Half-Duplex). | keyword |  |  |
| juniper.junos.interfaces.mac_address | Hardware MAC address assigned to the interface. | keyword |  |  |
| juniper.junos.interfaces.mac_statistics.input.broadcasts | Cumulative number of broadcast packets received at the MAC layer. | long |  | counter |
| juniper.junos.interfaces.mac_statistics.input.code_violations | Cumulative number of encoding violations detected at the PHY layer. | long |  | counter |
| juniper.junos.interfaces.mac_statistics.input.crc_errors | Cumulative number of CRC errors detected at the MAC layer on received frames. | long |  | counter |
| juniper.junos.interfaces.mac_statistics.input.fifo_errors | Cumulative number of MAC-layer input FIFO errors. | long |  | counter |
| juniper.junos.interfaces.mac_statistics.input.fragment_frames | Cumulative number of undersized fragment frames received. | long |  | counter |
| juniper.junos.interfaces.mac_statistics.input.jabber_frames | Cumulative number of malformed oversized frames received. | long |  | counter |
| juniper.junos.interfaces.mac_statistics.input.mac_control_frames | Cumulative number of IEEE 802.3 MAC control frames received. | long |  | counter |
| juniper.junos.interfaces.mac_statistics.input.mac_pause_frames | Cumulative number of flow control pause frames received. | long |  | counter |
| juniper.junos.interfaces.mac_statistics.input.multicasts | Cumulative number of multicast packets received at the MAC layer. | long |  | counter |
| juniper.junos.interfaces.mac_statistics.input.oversized_frames | Cumulative number of frames received larger than the configured MTU. | long |  | counter |
| juniper.junos.interfaces.mac_statistics.input.unicasts | Cumulative number of unicast packets received at the MAC layer. | long |  | counter |
| juniper.junos.interfaces.mac_statistics.input.vlan_tagged_frames | Cumulative number of 802.1Q VLAN-tagged frames received. | long |  | counter |
| juniper.junos.interfaces.mac_statistics.output.broadcasts | Cumulative number of broadcast packets transmitted at the MAC layer. | long |  | counter |
| juniper.junos.interfaces.mac_statistics.output.crc_errors | Cumulative number of CRC errors on transmitted frames. | long |  | counter |
| juniper.junos.interfaces.mac_statistics.output.fifo_errors | Cumulative number of MAC-layer output FIFO errors. | long |  | counter |
| juniper.junos.interfaces.mac_statistics.output.mac_control_frames | Cumulative number of IEEE 802.3 MAC control frames transmitted. | long |  | counter |
| juniper.junos.interfaces.mac_statistics.output.mac_pause_frames | Cumulative number of flow control pause frames transmitted. | long |  | counter |
| juniper.junos.interfaces.mac_statistics.output.multicasts | Cumulative number of multicast packets transmitted at the MAC layer. | long |  | counter |
| juniper.junos.interfaces.mac_statistics.output.unicasts | Cumulative number of unicast packets transmitted at the MAC layer. | long |  | counter |
| juniper.junos.interfaces.media_type | Physical media type of the interface (for example Fiber, Copper). | keyword |  |  |
| juniper.junos.interfaces.mtu | Maximum transmission unit size configured on the interface, in bytes. | long | byte | gauge |
| juniper.junos.interfaces.name | Interface name (for example ge-0/0/0, ae0, lo0). Used as a TSDB dimension. | keyword |  |  |
| juniper.junos.interfaces.oper_status | Operational status of the interface (up or down), reflecting the actual link state. | keyword |  |  |
| juniper.junos.interfaces.pcs.bit_error_seconds | Number of seconds with at least one PCS bit error detected. | long |  | counter |
| juniper.junos.interfaces.pcs.errored_blocks_seconds | Number of seconds with PCS errored blocks detected. | long |  | counter |
| juniper.junos.interfaces.snmp_index | SNMP ifIndex value assigned to this interface for SNMP polling. | long |  |  |
| juniper.junos.interfaces.source_filtering | Source address filtering state of the interface (enabled or turned off). | keyword |  |  |
| juniper.junos.interfaces.speed | Negotiated or configured interface speed (for example 1000mbps, 10Gbps, Auto). | keyword |  |  |
| juniper.junos.interfaces.traffic.input.bps | Current inbound traffic rate in bits per second. | long |  | gauge |
| juniper.junos.interfaces.traffic.input.bytes | Cumulative number of bytes received on the interface. | long | byte | counter |
| juniper.junos.interfaces.traffic.input.mbps | Current inbound traffic rate in megabits per second. | double |  | gauge |
| juniper.junos.interfaces.traffic.input.packets | Cumulative number of packets received on the interface. | long |  | counter |
| juniper.junos.interfaces.traffic.input.pps | Current inbound traffic rate in packets per second. | long |  | gauge |
| juniper.junos.interfaces.traffic.output.bps | Current outbound traffic rate in bits per second. | long |  | gauge |
| juniper.junos.interfaces.traffic.output.bytes | Cumulative number of bytes transmitted on the interface. | long | byte | counter |
| juniper.junos.interfaces.traffic.output.mbps | Current outbound traffic rate in megabits per second. | double |  | gauge |
| juniper.junos.interfaces.traffic.output.packets | Cumulative number of packets transmitted on the interface. | long |  | counter |
| juniper.junos.interfaces.traffic.output.pps | Current outbound traffic rate in packets per second. | long |  | gauge |
| juniper.junos.interfaces.type | Interface media type (for example Ethernet, SONET, Loopback). | keyword |  |  |
| observer.name | Device address configured for this integration instance, used as a TSDB dimension to distinguish devices. | keyword |  |  |
| observer.product | Observer product name. | keyword |  |  |
| observer.type | Observer type such as router, switch, or firewall. | keyword |  |  |
| observer.vendor | Observer vendor name. | keyword |  |  |


### Interface Queue Counters

The `interface_queues` data stream collects per-queue egress statistics for each physical interface. Each polling interval produces one event per queue per interface, with queued, transmitted, and dropped packet counts. Use this data to monitor QoS queue utilization and detect tail drops.

An example event for `interface_queues` looks as following:

```json
{
    "observer": {
        "vendor": "Juniper",
        "product": "JunOS",
        "type": "router",
        "name": "vJunOS-EX9214"
    },
    "juniper": {
        "junos": {
            "interface_queues": {
                "interface_name": "ge-0/0/0",
                "queue_number": 0,
                "forwarding_class": "best-effort",
                "queued_packets": 37398,
                "transmitted_packets": 37398,
                "dropped_packets": 0,
                "queues_supported": 10,
                "queues_in_use": 5
            }
        }
    },
    "event": {
        "dataset": "juniper_junos_metrics.interface_queues",
        "module": "juniper_junos_metrics",
        "kind": "metric",
        "category": [
            "network"
        ],
        "type": [
            "info"
        ]
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. | keyword |  |
| error.message | Error message. | match_only_text |  |
| event.category | Event category for ECS compatibility. | keyword |  |
| event.dataset | Event dataset. | constant_keyword |  |
| event.kind | The kind of event. | keyword |  |
| event.module | Event module. | constant_keyword |  |
| event.type | Event type for ECS compatibility. | keyword |  |
| juniper.junos.interface_queues.dropped_packets | Cumulative number of packets dropped from this queue due to congestion or policy. | long | counter |
| juniper.junos.interface_queues.forwarding_class | CoS forwarding class name mapped to this queue (for example best-effort, network-control). | keyword |  |
| juniper.junos.interface_queues.interface_name | Parent interface name (for example ge-0/0/0, ae0). Used as a TSDB dimension. | keyword |  |
| juniper.junos.interface_queues.queue_number | CoS queue number. Used as a TSDB dimension. | integer |  |
| juniper.junos.interface_queues.queued_packets | Cumulative number of packets enqueued on this queue. | long | counter |
| juniper.junos.interface_queues.queues_in_use | Number of CoS queues currently in use on the interface. | integer | gauge |
| juniper.junos.interface_queues.queues_supported | Total number of CoS queues supported on the interface. | integer | gauge |
| juniper.junos.interface_queues.transmitted_packets | Cumulative number of packets transmitted from this queue. | long | counter |
| observer.name | Device address configured for this integration instance, used as a TSDB dimension to distinguish devices. | keyword |  |
| observer.product | Observer product name. | keyword |  |
| observer.type | Observer type such as router, switch, or firewall. | keyword |  |
| observer.vendor | Observer vendor name. | keyword |  |


### BGP

The `bgp` data stream collects BGP peer summary information including peer state, AS numbers, route counts, and flap statistics. Each polling interval produces one event per BGP peer.

An example event for `bgp` looks as following:

```json
{
    "event": {
        "dataset": "juniper_junos_metrics.bgp",
        "kind": "metric",
        "module": "juniper_junos_metrics"
    },
    "juniper": {
        "junos": {
            "bgp": {
                "down_peer_count": 1,
                "group_count": 1,
                "peer": {
                    "address": "172.31.0.1",
                    "as": 65120,
                    "elapsed_time": 10281,
                    "flap_count": 0,
                    "input_messages": 0,
                    "output_messages": 0,
                    "state": "Active"
                },
                "peer_count": 1
            }
        }
    },
    "observer": {
        "product": "JunOS",
        "type": "router",
        "vendor": "Juniper"
    },
    "data_stream": {
        "type": "metrics",
        "dataset": "juniper_junos_metrics.bgp",
        "namespace": "default"
    },
    "ecs": {
        "version": "8.0.0"
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. | keyword |  |  |
| error.message | Error message. | match_only_text |  |  |
| event.category | Event category for ECS compatibility. | keyword |  |  |
| event.dataset | Event dataset. | constant_keyword |  |  |
| event.kind | The kind of event. | keyword |  |  |
| event.module | Event module. | constant_keyword |  |  |
| event.type | Event type for ECS compatibility. | keyword |  |  |
| juniper.junos.bgp.down_peer_count | Number of BGP peers not in the Established state. | long |  | gauge |
| juniper.junos.bgp.group_count | Total number of BGP peer groups configured on the router. | long |  | gauge |
| juniper.junos.bgp.peer.accepted_prefix_count | Total accepted prefix count across all address families for this peer. | long |  | gauge |
| juniper.junos.bgp.peer.active_prefix_count | Total active prefix count across all address families for this peer. | long |  | gauge |
| juniper.junos.bgp.peer.address | IP address of the BGP peer. Used as a TSDB dimension. | keyword |  |  |
| juniper.junos.bgp.peer.as | Autonomous system number of the remote BGP peer. Used as a TSDB dimension. | long |  |  |
| juniper.junos.bgp.peer.description | Operator-configured description for the BGP peer group or neighbor. | keyword |  |  |
| juniper.junos.bgp.peer.elapsed_time | Seconds elapsed after the most recent BGP state change for this peer. | long | s | gauge |
| juniper.junos.bgp.peer.flap_count | Number of times this peer session has transitioned away from Established state. | long |  | counter |
| juniper.junos.bgp.peer.input_messages | Cumulative number of BGP messages received from this peer. | long |  | counter |
| juniper.junos.bgp.peer.output_messages | Cumulative number of BGP messages sent to this peer. | long |  | counter |
| juniper.junos.bgp.peer.received_prefix_count | Total received prefix count across all address families for this peer. | long |  | gauge |
| juniper.junos.bgp.peer.route_queue_count | Number of routes queued for this peer. | long |  | gauge |
| juniper.junos.bgp.peer.state | Current BGP FSM state of the peer (for example Established, Active, Connect, OpenSent). | keyword |  |  |
| juniper.junos.bgp.peer.suppressed_prefix_count | Total suppressed (dampened) prefix count across all address families for this peer. | long |  | gauge |
| juniper.junos.bgp.peer_count | Total number of configured BGP peers across all groups. | long |  | gauge |
| observer.name | Device address configured for this integration instance, used as a TSDB dimension to distinguish devices. | keyword |  |  |
| observer.product | Observer product name. | keyword |  |  |
| observer.type | Observer type such as router, switch, or firewall. | keyword |  |  |
| observer.vendor | Observer vendor name. | keyword |  |  |


### OSPF

The `ospf` data stream collects OSPF area overview information including area ID, ABR and ASBR counts, neighbor counts, and stub configuration. Each polling interval produces one event per OSPF area.

An example event for `ospf` looks as following:

```json
{
    "event": {
        "dataset": "juniper_junos_metrics.ospf",
        "kind": "metric",
        "module": "juniper_junos_metrics"
    },
    "juniper": {
        "junos": {
            "ospf": {
                "area": {
                    "abr_count": 0,
                    "asbr_count": 0,
                    "authentication_type": "None",
                    "id": "0.0.0.0",
                    "neighbor_up_count": 0,
                    "stub_type": "Not Stub"
                },
                "instance_name": "master",
                "router_id": "172.31.0.120"
            }
        }
    },
    "observer": {
        "product": "JunOS",
        "type": "router",
        "vendor": "Juniper"
    },
    "data_stream": {
        "type": "metrics",
        "dataset": "juniper_junos_metrics.ospf",
        "namespace": "default"
    },
    "ecs": {
        "version": "8.0.0"
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. | keyword |  |
| error.message | Error message. | match_only_text |  |
| event.category | Event category for ECS compatibility. | keyword |  |
| event.dataset | Event dataset. | constant_keyword |  |
| event.kind | The kind of event. | keyword |  |
| event.module | Event module. | constant_keyword |  |
| event.type | Event type for ECS compatibility. | keyword |  |
| juniper.junos.ospf.area.abr_count | Number of Area Border Routers (ABRs) detected in this OSPF area. | long | gauge |
| juniper.junos.ospf.area.asbr_count | Number of Autonomous System Boundary Routers (ASBRs) detected in this OSPF area. | long | gauge |
| juniper.junos.ospf.area.authentication_type | Authentication method configured for the area (for example None, MD5, plain text). | keyword |  |
| juniper.junos.ospf.area.id | OSPF area identifier in dotted-decimal notation (for example 0.0.0.0 for backbone). Used as a TSDB dimension. | keyword |  |
| juniper.junos.ospf.area.neighbor_up_count | Number of OSPF neighbors in Full adjacency state within this area. | long | gauge |
| juniper.junos.ospf.area.stub_type | Area stub configuration type (for example Not Stub, Stub, NSSA). | keyword |  |
| juniper.junos.ospf.instance_name | Name of the OSPF routing instance. Used as a TSDB dimension. | keyword |  |
| juniper.junos.ospf.router_id | OSPF router ID in dotted-decimal notation. Used as a TSDB dimension. | keyword |  |
| observer.name | Device address configured for this integration instance, used as a TSDB dimension to distinguish devices. | keyword |  |
| observer.product | Observer product name. | keyword |  |
| observer.type | Observer type such as router, switch, or firewall. | keyword |  |
| observer.vendor | Observer vendor name. | keyword |  |


### Routing Table

The `routing_table` data stream collects routing table summary statistics including active, total, holddown, and hidden route counts per table. Each polling interval produces one event per routing table.

An example event for `routing_table` looks as following:

```json
{
    "event": {
        "dataset": "juniper_junos_metrics.routing_table",
        "kind": "metric",
        "module": "juniper_junos_metrics"
    },
    "juniper": {
        "junos": {
            "routing_table": {
                "active_route_count": 5,
                "destination_count": 5,
                "hidden_route_count": 0,
                "holddown_route_count": 0,
                "router_id": "172.31.0.120",
                "table_name": "inet.0",
                "total_route_count": 5
            }
        }
    },
    "observer": {
        "product": "JunOS",
        "type": "router",
        "vendor": "Juniper"
    },
    "data_stream": {
        "type": "metrics",
        "dataset": "juniper_junos_metrics.routing_table",
        "namespace": "default"
    },
    "ecs": {
        "version": "8.0.0"
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. | keyword |  |
| error.message | Error message. | match_only_text |  |
| event.category | Event category for ECS compatibility. | keyword |  |
| event.dataset | Event dataset. | constant_keyword |  |
| event.kind | The kind of event. | keyword |  |
| event.module | Event module. | constant_keyword |  |
| event.type | Event type for ECS compatibility. | keyword |  |
| juniper.junos.routing_table.active_route_count | Number of routes currently selected as best path and installed in the forwarding table. | long | gauge |
| juniper.junos.routing_table.destination_count | Number of unique destination prefixes in the routing table. | long | gauge |
| juniper.junos.routing_table.hidden_route_count | Number of routes hidden due to import policy rejection or next-hop resolution failure. | long | gauge |
| juniper.junos.routing_table.holddown_route_count | Number of routes in holddown state, pending deletion after withdrawal. | long | gauge |
| juniper.junos.routing_table.router_id | Router ID of the device in dotted-decimal notation. Used as a TSDB dimension. | keyword |  |
| juniper.junos.routing_table.table_name | Routing table name (for example inet.0, inet6.0, mpls.0). Used as a TSDB dimension. | keyword |  |
| juniper.junos.routing_table.total_route_count | Total number of routes in the routing table, including inactive and hidden routes. | long | gauge |
| observer.name | Device address configured for this integration instance, used as a TSDB dimension to distinguish devices. | keyword |  |
| observer.product | Observer product name. | keyword |  |
| observer.type | Observer type such as router, switch, or firewall. | keyword |  |
| observer.vendor | Observer vendor name. | keyword |  |


### Storage

The `storage` data stream collects filesystem usage statistics including total, used, and available bytes, and utilization percentage. Each polling interval produces one event per mounted filesystem.

An example event for `storage` looks as following:

```json
{
    "event": {
        "dataset": "juniper_junos_metrics.storage",
        "kind": "metric",
        "module": "juniper_junos_metrics"
    },
    "juniper": {
        "junos": {
            "storage": {
                "available_bytes": 35166560256,
                "filesystem_name": "/dev/gpt/junos",
                "mounted_on": "/.mount",
                "total_bytes": 42268352512,
                "used_bytes": 3720331264,
                "used_percent": 10.0
            }
        }
    },
    "observer": {
        "product": "JunOS",
        "type": "router",
        "vendor": "Juniper"
    },
    "data_stream": {
        "type": "metrics",
        "dataset": "juniper_junos_metrics.storage",
        "namespace": "default"
    },
    "ecs": {
        "version": "8.0.0"
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. | keyword |  |  |
| error.message | Error message. | match_only_text |  |  |
| event.category | Event category for ECS compatibility. | keyword |  |  |
| event.dataset | Event dataset. | constant_keyword |  |  |
| event.kind | The kind of event. | keyword |  |  |
| event.module | Event module. | constant_keyword |  |  |
| event.type | Event type for ECS compatibility. | keyword |  |  |
| juniper.junos.storage.available_bytes | Number of bytes available for use on the filesystem. | long | byte | gauge |
| juniper.junos.storage.filesystem_name | Filesystem device path (for example /dev/gpt/junos). Used as a TSDB dimension. | keyword |  |  |
| juniper.junos.storage.mounted_on | Directory where the filesystem is mounted (for example /junos, /var). Used as a TSDB dimension. | keyword |  |  |
| juniper.junos.storage.total_bytes | Total capacity of the filesystem in bytes. | long | byte | gauge |
| juniper.junos.storage.used_bytes | Number of bytes currently consumed on the filesystem. | long | byte | gauge |
| juniper.junos.storage.used_percent | Percentage of filesystem capacity currently in use. | float | percent | gauge |
| observer.name | Device address configured for this integration instance, used as a TSDB dimension to distinguish devices. | keyword |  |  |
| observer.product | Observer product name. | keyword |  |  |
| observer.type | Observer type such as router, switch, or firewall. | keyword |  |  |
| observer.vendor | Observer vendor name. | keyword |  |  |


### Environment

The `environment` data stream collects hardware environmental sensor readings including temperatures, fan status, and power supply status. Each polling interval produces one event per monitored component.

An example event for `environment` looks as following:

```json
{
    "event": {
        "dataset": "juniper_junos_metrics.environment",
        "kind": "metric",
        "module": "juniper_junos_metrics"
    },
    "juniper": {
        "junos": {
            "environment": {
                "class": "Temp",
                "comment": "Testing only",
                "name": "Routing Engine 0",
                "status": "OK",
                "temperature": 45.0
            }
        }
    },
    "observer": {
        "product": "JunOS",
        "type": "router",
        "vendor": "Juniper"
    },
    "data_stream": {
        "type": "metrics",
        "dataset": "juniper_junos_metrics.environment",
        "namespace": "default"
    },
    "ecs": {
        "version": "8.0.0"
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. | keyword |  |
| error.message | Error message. | match_only_text |  |
| event.category | Event category for ECS compatibility. | keyword |  |
| event.dataset | Event dataset. | constant_keyword |  |
| event.kind | The kind of event. | keyword |  |
| event.module | Event module. | constant_keyword |  |
| event.type | Event type for ECS compatibility. | keyword |  |
| juniper.junos.environment.class | Category of the environmental sensor (for example Temp, Fans, Power). | keyword |  |
| juniper.junos.environment.comment | Supplemental detail from Junos about the component state (for example fan RPM, power draw). | keyword |  |
| juniper.junos.environment.name | Name of the hardware component being monitored (for example Routing Engine 0, FPC 0 CPU, PSU 0). Used as a TSDB dimension. | keyword |  |
| juniper.junos.environment.status | Health status reported by the component (for example OK, Check, Failed, Absent). | keyword |  |
| juniper.junos.environment.temperature | Temperature reading from the component sensor in degrees Celsius, if applicable. | float | gauge |
| observer.name | Device address configured for this integration instance, used as a TSDB dimension to distinguish devices. | keyword |  |
| observer.product | Observer product name. | keyword |  |
| observer.type | Observer type such as router, switch, or firewall. | keyword |  |
| observer.vendor | Observer vendor name. | keyword |  |


### Alarm

The `alarm` data stream collects active system alarms including severity, type, and description. Each polling interval produces one event per active alarm.

An example event for `alarm` looks as following:

```json
{
    "@timestamp": "2026-03-10T08:02:45Z",
    "event": {
        "dataset": "juniper_junos_metrics.alarm",
        "kind": "event",
        "module": "juniper_junos_metrics"
    },
    "juniper": {
        "junos": {
            "alarm": {
                "class": "Major",
                "description": "FPC 0 Hard errors",
                "short_description": "FPC 0 Hard errors",
                "time": "2026-03-10T08:02:45Z",
                "type": "Chassis"
            }
        }
    },
    "observer": {
        "product": "JunOS",
        "type": "router",
        "vendor": "Juniper"
    },
    "data_stream": {
        "type": "logs",
        "dataset": "juniper_junos_metrics.alarm",
        "namespace": "default"
    },
    "ecs": {
        "version": "8.0.0"
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. | keyword |
| error.message | Error message. | match_only_text |
| event.category | Event category for ECS compatibility. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | The kind of event. | keyword |
| event.module | Event module. | constant_keyword |
| event.type | Event type for ECS compatibility. | keyword |
| juniper.junos.alarm.class | Severity class of the alarm (for example Major, Minor). | keyword |
| juniper.junos.alarm.description | Full human-readable alarm message as reported by Junos. | keyword |
| juniper.junos.alarm.short_description | Abbreviated alarm message suitable for display in summary views. | keyword |
| juniper.junos.alarm.time | Timestamp when the alarm was raised by Junos. | date |
| juniper.junos.alarm.type | Subsystem that generated the alarm (for example Interface, Chassis, Configuration). | keyword |
| observer.name | Device name or address configured for this integration instance. | keyword |
| observer.product | Observer product name. | keyword |
| observer.type | Observer type such as router, switch, or firewall. | keyword |
| observer.vendor | Observer vendor name. | keyword |


### ARP Table

The `arp` data stream collects ARP table entries from the device. Each polling interval produces one event per ARP entry, with MAC address, IP address, and interface name. The total ARP entry count is included on each event for capacity monitoring.

An example event for `arp` looks as following:

```json
{
    "@timestamp": "2026-03-10T19:00:00.000Z",
    "data_stream": {
        "type": "metrics",
        "dataset": "juniper_junos_metrics.arp",
        "namespace": "default"
    },
    "event": {
        "kind": "metric",
        "module": "juniper_junos_metrics",
        "dataset": "juniper_junos_metrics.arp"
    },
    "observer": {
        "vendor": "Juniper",
        "product": "JunOS",
        "type": "router",
        "name": "vJunOS-EX9214"
    },
    "juniper": {
        "junos": {
            "arp": {
                "ip_address": "172.31.0.1",
                "mac_address": "fe:ad:e5:18:29:dc",
                "hostname": "172.31.0.1",
                "interface": "fxp0.0",
                "entry_count": 3
            }
        }
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. | keyword |  |
| error.message | Error message. | match_only_text |  |
| event.category | Event category for ECS compatibility. | keyword |  |
| event.dataset | Event dataset. | constant_keyword |  |
| event.kind | The kind of event. | keyword |  |
| event.module | Event module. | constant_keyword |  |
| event.type | Event type for ECS compatibility. | keyword |  |
| juniper.junos.arp.entry_count | Total number of ARP entries in the table. | long | gauge |
| juniper.junos.arp.entry_flags | ARP entry flags indicating entry type (for example permanent, none). | keyword |  |
| juniper.junos.arp.hostname | Resolved hostname for the ARP entry, if available. | keyword |  |
| juniper.junos.arp.interface | Interface on which the ARP entry was learned. | keyword |  |
| juniper.junos.arp.ip_address | IP address of the ARP entry. | ip |  |
| juniper.junos.arp.mac_address | MAC address associated with the IP address. | keyword |  |
| observer.name | Device address configured for this integration instance, used as a TSDB dimension to distinguish devices. | keyword |  |
| observer.product | Observer product name. | keyword |  |
| observer.type | Observer type such as router, switch, or firewall. | keyword |  |
| observer.vendor | Observer vendor name. | keyword |  |


### LLDP Neighbors

The `lldp` data stream collects LLDP neighbor information from the device. Each polling interval produces one event per LLDP neighbor, with local port, remote chassis ID, remote system name, and remote port description.

An example event for `lldp` looks as following:

```json
{
    "@timestamp": "2026-03-10T19:00:00.000Z",
    "data_stream": {
        "type": "metrics",
        "dataset": "juniper_junos_metrics.lldp",
        "namespace": "default"
    },
    "event": {
        "kind": "metric",
        "module": "juniper_junos_metrics",
        "dataset": "juniper_junos_metrics.lldp"
    },
    "observer": {
        "vendor": "Juniper",
        "product": "JunOS",
        "type": "router",
        "name": "vJunOS-EX9214"
    },
    "juniper": {
        "junos": {
            "lldp": {
                "local_port": "ge-0/0/0",
                "remote": {
                    "chassis_id": "aa:bb:cc:dd:ee:ff",
                    "port_id": "GigabitEthernet0/1",
                    "port_description": "Uplink to core",
                    "system_name": "switch-01.example.com"
                },
                "neighbor_count": 2
            }
        }
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. | keyword |  |
| error.message | Error message. | match_only_text |  |
| event.category | Event category for ECS compatibility. | keyword |  |
| event.dataset | Event dataset. | constant_keyword |  |
| event.kind | The kind of event. | keyword |  |
| event.module | Event module. | constant_keyword |  |
| event.type | Event type for ECS compatibility. | keyword |  |
| juniper.junos.lldp.local_parent_interface | LAG or aggregate interface that the local port belongs to (for example ae0, ae45). | keyword |  |
| juniper.junos.lldp.local_port | Local port on which the LLDP neighbor was discovered. | keyword |  |
| juniper.junos.lldp.neighbor_count | Total number of LLDP neighbors discovered. | long | gauge |
| juniper.junos.lldp.remote.chassis_id | Remote neighbor chassis identifier. | keyword |  |
| juniper.junos.lldp.remote.port_description | Description of the remote neighbor port. | keyword |  |
| juniper.junos.lldp.remote.port_id | Remote neighbor port identifier. | keyword |  |
| juniper.junos.lldp.remote.system_name | System name of the remote LLDP neighbor. | keyword |  |
| observer.name | Device address configured for this integration instance, used as a TSDB dimension to distinguish devices. | keyword |  |
| observer.product | Observer product name. | keyword |  |
| observer.type | Observer type such as router, switch, or firewall. | keyword |  |
| observer.vendor | Observer vendor name. | keyword |  |


### System Users

The `system` data stream collects active user session information from the device. Each polling interval produces one event per logged-in user, with username, TTY, source address, login time, idle time, and command.

An example event for `system` looks as following:

```json
{
    "event": {
        "dataset": "juniper_junos_metrics.system",
        "kind": "metric",
        "module": "juniper_junos_metrics"
    },
    "juniper": {
        "junos": {
            "system": {
                "active_user_count": 1,
                "user": {
                    "name": "admin",
                    "tty": "pts/0",
                    "from": "10.0.0.50",
                    "login_time": "2025-03-10T08:10:00Z",
                    "idle_time": 120,
                    "command": "-cli (cli)"
                }
            }
        }
    },
    "observer": {
        "product": "JunOS",
        "type": "router",
        "vendor": "Juniper"
    },
    "data_stream": {
        "type": "metrics",
        "dataset": "juniper_junos_metrics.system",
        "namespace": "default"
    },
    "ecs": {
        "version": "8.0.0"
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. | keyword |  |  |
| error.message | Error message. | match_only_text |  |  |
| event.category | Event category for ECS compatibility. | keyword |  |  |
| event.dataset | Event dataset. | constant_keyword |  |  |
| event.kind | The kind of event. | keyword |  |  |
| event.module | Event module. | constant_keyword |  |  |
| event.type | Event type for ECS compatibility. | keyword |  |  |
| juniper.junos.system.active_user_count | Number of users currently logged into the device. | long |  | gauge |
| juniper.junos.system.user.command | Current command or shell running. | keyword |  |  |
| juniper.junos.system.user.from | Source IP or host of the session. | keyword |  |  |
| juniper.junos.system.user.idle_time | Seconds the session has been idle. | long | s | gauge |
| juniper.junos.system.user.login_time | Time the user logged in. | date |  |  |
| juniper.junos.system.user.name | Username of the logged-in user. | keyword |  |  |
| juniper.junos.system.user.tty | Terminal or PTY of the session. | keyword |  |  |
| observer.name | Device address configured for this integration instance, used as a TSDB dimension to distinguish devices. | keyword |  |  |
| observer.product | Observer product name. | keyword |  |  |
| observer.type | Observer type such as router, switch, or firewall. | keyword |  |  |
| observer.vendor | Observer vendor name. | keyword |  |  |


### System Information

The `system_info` data stream collects device identity information including hostname, hardware model, OS version, and serial number. It also retrieves the most recent configuration change timestamp and user. This data stream polls infrequently and is useful for inventory and compliance dashboards.

An example event for `system_info` looks as following:

```json
{
    "event": {
        "dataset": "juniper_junos_metrics.system_info",
        "kind": "metric",
        "module": "juniper_junos_metrics"
    },
    "host": {
        "name": "vJunOS-EX9214"
    },
    "juniper": {
        "junos": {
            "system_info": {
                "hostname": "vJunOS-EX9214",
                "hardware_model": "ex9214",
                "os_name": "junos",
                "os_version": "25.4R1.12",
                "serial_number": "VM69AFCB3145",
                "up": 1
            }
        }
    },
    "observer": {
        "product": "JunOS",
        "type": "router",
        "vendor": "Juniper"
    },
    "data_stream": {
        "type": "metrics",
        "dataset": "juniper_junos_metrics.system_info",
        "namespace": "default"
    },
    "ecs": {
        "version": "8.0.0"
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. | keyword |  |
| error.message | Error message. | match_only_text |  |
| event.category | Event category for ECS compatibility. | keyword |  |
| event.dataset | Event dataset. | constant_keyword |  |
| event.kind | The kind of event. | keyword |  |
| event.module | Event module. | constant_keyword |  |
| event.type | Event type for ECS compatibility. | keyword |  |
| host.name | Device hostname reported by the system. | keyword |  |
| juniper.junos.system_info.hardware_model | Hardware model identifier of the device. | keyword |  |
| juniper.junos.system_info.hostname | Device hostname as reported by the system. | keyword |  |
| juniper.junos.system_info.os_name | Operating system name (for example junos). | keyword |  |
| juniper.junos.system_info.os_version | Operating system version string. | keyword |  |
| juniper.junos.system_info.serial_number | Device chassis serial number. | keyword |  |
| juniper.junos.system_info.up | Device reachability indicator. Always 1 when the device responds to API requests. | short | gauge |
| observer.name | Device address configured for this integration instance, used as a TSDB dimension to distinguish devices. | keyword |  |
| observer.product | Observer product name. | keyword |  |
| observer.type | Observer type such as router, switch, or firewall. | keyword |  |
| observer.vendor | Observer vendor name. | keyword |  |

