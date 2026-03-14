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

{{event "route_engine"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "route_engine"}}

### Interfaces

The `interfaces` data stream collects per-interface traffic and error metrics. Each polling interval produces one event per physical interface. Fields include byte and packet counters, rate gauges, error counts, and drop counts. OTel-aligned `system.network.*` fields aggregate the per-direction counters.

{{event "interfaces"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "interfaces"}}

### Interface Queue Counters

The `interface_queues` data stream collects per-queue egress statistics for each physical interface. Each polling interval produces one event per queue per interface, with queued, transmitted, and dropped packet counts. Use this data to monitor QoS queue utilization and detect tail drops.

{{event "interface_queues"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "interface_queues"}}

### BGP

The `bgp` data stream collects BGP peer summary information including peer state, AS numbers, route counts, and flap statistics. Each polling interval produces one event per BGP peer.

{{event "bgp"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "bgp"}}

### OSPF

The `ospf` data stream collects OSPF area overview information including area ID, ABR and ASBR counts, neighbor counts, and stub configuration. Each polling interval produces one event per OSPF area.

{{event "ospf"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "ospf"}}

### Routing Table

The `routing_table` data stream collects routing table summary statistics including active, total, holddown, and hidden route counts per table. Each polling interval produces one event per routing table.

{{event "routing_table"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "routing_table"}}

### Storage

The `storage` data stream collects filesystem usage statistics including total, used, and available bytes, and utilization percentage. Each polling interval produces one event per mounted filesystem.

{{event "storage"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "storage"}}

### Environment

The `environment` data stream collects hardware environmental sensor readings including temperatures, fan status, and power supply status. Each polling interval produces one event per monitored component.

{{event "environment"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "environment"}}

### Alarm

The `alarm` data stream collects active system alarms including severity, type, and description. Each polling interval produces one event per active alarm.

{{event "alarm"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "alarm"}}

### ARP Table

The `arp` data stream collects ARP table entries from the device. Each polling interval produces one event per ARP entry, with MAC address, IP address, and interface name. The total ARP entry count is included on each event for capacity monitoring.

{{event "arp"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "arp"}}

### LLDP Neighbors

The `lldp` data stream collects LLDP neighbor information from the device. Each polling interval produces one event per LLDP neighbor, with local port, remote chassis ID, remote system name, and remote port description.

{{event "lldp"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "lldp"}}

### System Users

The `system` data stream collects active user session information from the device. Each polling interval produces one event per logged-in user, with username, TTY, source address, login time, idle time, and command.

{{event "system"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "system"}}

### System Information

The `system_info` data stream collects device identity information including hostname, hardware model, OS version, and serial number. It also retrieves the most recent configuration change timestamp and user. This data stream polls infrequently and is useful for inventory and compliance dashboards.

{{event "system_info"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "system_info"}}
