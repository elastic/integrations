# Proxmox VE Integration

The Proxmox VE integration collects metrics and logs from [Proxmox Virtual Environment](https://www.proxmox.com/en/proxmox-virtual-environment/overview) hosts. It polls the Proxmox REST API for cluster and node metrics and reads local log files and systemd journal entries for operational events.

## Compatibility

This integration has been tested with Proxmox VE 8.x and 9.x.

## Setup

1. Create a dedicated monitoring user and API token on your Proxmox host:

```bash
pveum user add monitor@pve
pveum aclmod / -user monitor@pve -role PVEAuditor
pveum user token add monitor@pve elastic --privsep=0
```

2. Install Elastic Agent on the Proxmox host.

3. Add the Proxmox VE integration in Fleet, providing:
   - The Proxmox API URL (for example, `https://192.168.1.1:8006`)
   - The API token ID in `USER@REALM!TOKENID` format (for example, `monitor@pve!elastic`)
   - The API token secret (UUID)
   - The node hostname

## Data Streams

### Cluster Metrics

Cluster-wide resource metrics collected from the Proxmox REST API. Includes CPU, memory, disk, and network statistics for all nodes, VMs, containers, and storage pools, along with cluster quorum status and HA resource state.

{{event "cluster"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "cluster"}}

### Node Metrics

Detailed per-node metrics collected from the Proxmox REST API, including CPU usage, load averages, memory and swap usage, root filesystem usage, and system information.

{{event "node"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "node"}}

### Access Logs

HTTP access logs from the Proxmox web proxy (pveproxy). Each entry records the client IP, authenticated user, request method and path, HTTP status code, and response size.

{{event "access"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "access"}}

### Firewall Logs

Proxmox VE firewall log entries from pve-firewall.log. Each entry records the firewall action (DROP, REJECT, ACCEPT), source and destination IPs, ports, protocol, and packet metadata.

{{event "firewall"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "firewall"}}

### Auth Events

Authentication events from the pvedaemon systemd journal. Records successful and failed login attempts with the authenticating user, source IP, and realm.

{{event "auth"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "auth"}}

### Cluster Logs

Corosync cluster events from the systemd journal. Records membership changes, quorum transitions, and link state changes.

{{event "cluster_logs"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "cluster_logs"}}

### Tasks

Task completion records from the Proxmox task index. Each entry records the task type, target VM or container, executing user, duration, and outcome.

{{event "tasks"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "tasks"}}
