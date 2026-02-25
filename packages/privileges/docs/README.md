# SAP Privileges

The SAP Privileges integration collects and parses privilege-related events from [SAP Privileges](https://github.com/SAP/macOS-enterprise-privileges) for macOS. SAP Privileges is a free macOS application designed for modern enterprise environments that gives users temporary administrator privileges when needed without granting permanent admin rights.

## Data streams

The SAP Privileges integration collects the following event types: `log`.

## Compatibility

This module has been tested against SAP Privileges Version 2.x and should work with all versions.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### Configure SAP Privileges to send logs

To configure SAP Privileges to send logs to your Elastic stack:

1. **Create a configuration profile** with the `RemoteLogging` key:
   - Set `ServerType` to `syslog` or `webhook`
   - Set `ServerAddress` to the hostname or IP address of your syslog server or webhook URL
   - For syslog, configure the `SyslogOptions` dictionary with:
     - `ServerPort` (default: 514 or 6514 if TLS is enabled)
     - `UseTLS` (boolean, default: false)
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

Below are sample logs from SAP Privileges:

### Privilege Grant/Revoke Logs

```
<134>2025-01-23T09:49:10.000+05:00 SRV-MAC-001 Privileges: User john.doe granted admin privileges for 1 hour
<134>2025-01-23T10:49:10.000+05:00 SRV-MAC-001 Privileges: User john.doe admin privileges revoked
<134>2025-01-23T11:30:00.000+05:00 SRV-MAC-001 Privileges: User jane.smith granted admin privileges for 30 minutes
```

### Authentication Logs

```
<134>2025-01-23T12:00:00.000+05:00 SRV-MAC-001 Privileges: User john.doe authenticated successfully using Touch ID
<134>2025-01-23T12:05:00.000+05:00 SRV-MAC-001 Privileges: User jane.smith authentication failed - incorrect password
<134>2025-01-23T12:10:00.000+05:00 SRV-MAC-001 Privileges: User bob.jones authenticated successfully using password
```

### Privilege Renewal Logs

```
<134>2025-01-23T13:00:00.000+05:00 SRV-MAC-001 Privileges: User john.doe renewed admin privileges for 1 hour
<134>2025-01-23T13:05:00.000+05:00 SRV-MAC-001 Privileges: User jane.smith privilege renewal notification sent
```

## Logs

This is the `log` dataset.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2025-01-23T09:49:10.000+05:00",
    "agent": {
        "ephemeral_id": "e3830e56-f9b7-4278-b2cc-6c0041b3204b",
        "id": "92657501-44cd-4942-ab49-19404cc15d88",
        "name": "elastic-agent-47754",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "client": {
        "ip": "192.168.1.100"
    },
    "data_stream": {
        "dataset": "sap_privileges.log",
        "namespace": "63231",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "92657501-44cd-4942-ab49-19404cc15d88",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2025-01-23T09:49:10.000+05:00",
        "dataset": "sap_privileges.log",
        "ingested": "2025-05-30T11:05:38Z",
        "kind": "event",
        "original": "<134>2025-01-23T09:49:10.000+05:00 SRV-MAC-001 Privileges: User john.doe granted admin privileges for 1 hour",
        "outcome": "success",
        "timezone": "+0500"
    },
    "host": {
        "hostname": "SRV-MAC-001"
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "source": {
            "address": "192.168.255.3:58871"
        },
        "syslog": {
            "priority": 134
        }
    },
    "message": "User john.doe granted admin privileges for 1 hour",
    "tags": [
        "preserve_original_event",
        "forwarded",
        "sap_privileges-log"
    ],
    "user": {
        "name": "john.doe"
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
| privilege.duration | Duration for which privileges were granted | keyword |
| privilege.outcome | Outcome of the privilege request (granted/denied) | keyword |
