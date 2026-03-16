# SAP Privileges

The SAP Privileges integration collects and parses privilege-related events
from [SAP Privileges](https://github.com/SAP/macOS-enterprise-privileges) for macOS.
SAP Privileges is a free macOS application designed for modern enterprise environments that gives users temporary
administrator privileges when needed without granting permanent admin rights.

## Data streams

The SAP Privileges integration collects the following event types: `log`.

## Compatibility

This module has been tested against SAP Privileges Version 2.x and should work with all versions.

## Requirements

Elastic Agent must be installed.
For more details, check the Elastic
Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### Configure SAP Privileges to send logs

To configure SAP Privileges to send logs to your Elastic stack. Product specific manual can be
found [here](https://github.com/SAP/macOS-enterprise-privileges/wiki/Managing-Privileges#SyslogOptions):

1. **Create a configuration profile** with the `RemoteLogging` key:
    - Set `ServerType` to `syslog`
    - Set `ServerAddress` to the hostname or IP address of your syslog server
    - For syslog, configure the `SyslogOptions` dictionary with:
        - `ServerPort` (Integration default: 5040 TCP)
        - Optional `UseTLS` (boolean, default: false)
        - `LogFacility` (default: 4 - security)
        - `LogSeverity` (default: 6 - informational)
        - `MaximumMessageSize` (default: 480 bytes)

2. **Example configuration profile** (for syslog with TLS):
   ```xml
   <key>RemoteLogging</key>
   <dict>
       <key>ServerType</key>
       <string>syslog</string>
       <key>ServerAddress</key>
       <string>your-syslog-server.example.com</string>
       <key>SyslogOptions</key>
       <dict>
           <key>ServerPort</key>
           <integer>6514</integer>
           <key>UseTLS</key>
           <true/>
           <key>LogFacility</key>
           <integer>4</integer>
           <key>LogSeverity</key>
           <integer>6</integer>
           <key>MaximumMessageSize</key>
           <integer>480</integer>
       </dict>
   </dict>
   ```

3. **Deploy the configuration profile** to your macOS devices using your MDM solution

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**
2. In the search top bar, type **SAP Privileges**
3. Select the **SAP Privileges** integration and add it
4. Add all the required integration configuration parameters:
    - Set the correct host and port to match your SAP Privileges configuration
    - Choose TCP or UDP based on your SAP Privileges setup
5. Save the integration

## Log samples

Below are the sample logs of the respective category.

### Audit Logs

```
<134>2025-01-23T13:00:00.000+05:00 SRV-MAC-001 Privileges: User john.doe renewed admin privileges for 1 hour
<134>2025-01-23T13:05:00.000+05:00 SRV-MAC-001 Privileges: User jane.smith privilege renewal notification sent
```

## Logs

This is the `log` dataset.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2026-02-24T14:16:11.133Z",
    "agent": {
        "ephemeral_id": "da16c0fd-c89b-46d5-a0d6-3d0525658cfe",
        "id": "7aa96830-99fa-4b6c-bc2c-cdfdf2f16f4b",
        "name": "elastic-agent-35579",
        "type": "filebeat",
        "version": "9.0.0"
    },
    "data_stream": {
        "dataset": "privileges.log",
        "namespace": "59093",
        "type": "logs"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "elastic_agent": {
        "id": "7aa96830-99fa-4b6c-bc2c-cdfdf2f16f4b",
        "snapshot": false,
        "version": "9.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2026-02-24T14:16:11.133Z",
        "dataset": "privileges.log",
        "ingested": "2026-03-16T18:07:37Z",
        "kind": "event",
        "original": "<135>1 2026-02-24T14:16:11.133Z device001 Privileges 857 PRIV_S - ﻿SAPCorp: User jdoe now has standard user privileges (requested by user)",
        "timezone": "+0500"
    },
    "host": {
        "hostname": "device001"
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "source": {
            "address": "172.21.0.3:50131"
        },
        "syslog": {
            "priority": 135,
            "version": "1"
        }
    },
    "message": "User jdoe now has standard user privileges (requested by user)",
    "privilege": {
        "type": "PRIV_S"
    },
    "process": {
        "pid": 857
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "sap_privileges-log"
    ],
    "user": {
        "name": "jdoe"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Log source address | keyword |
| privilege.reason | The reason given to elevate privileges | keyword |
| privilege.type | Privilege Type that was applied (User or Administrative) | keyword |

