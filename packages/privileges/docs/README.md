# SAP Privileges

The SAP Privileges integration collects and parses privilege-related events
from [SAP Privileges](https://github.com/SAP/macOS-enterprise-privileges) for macOS.
SAP Privileges is a free macOS application designed for modern enterprise environments that gives users temporary
administrator privileges when needed without granting permanent admin rights.

## Overview

### Compatibility

This module has been tested against SAP Privileges Version 2.x and should work with all versions.

### How it works

The integration collects privilege-related events from SAP Privileges and parses them into structured logs. It monitors
privilege escalation events and privilege expiration events to provide visibility into administrator privilege usage
across macOS devices in enterprise environments.

## What data does this integration collect?

The SAP Privileges integration collects log data from SAP Privileges application on macOS devices. The integration
supports the following use cases:

- Monitor privilege escalation events
- Track privilege expiration

## What do I need to use this integration?

- Elastic Agent must be installed on your macOS devices or as a centralised syslog server on a platform of your choice. 
- SAP Privileges application must be installed and configured to send logs to your syslog server if the Agent is used as a syslog server.
- Appropriate permissions to configure SAP Privileges and deploy configuration profiles via MDM or locally.

For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## How do I deploy this integration?

### Onboard and configure

1. **Install and configure SAP Privileges**:
    - Install SAP Privileges on your macOS devices
    - Configure SAP Privileges to send logs to your Elastic stack

2. **Configure SAP Privileges to send logs**:
   Product specific manual can be
   found [here](https://github.com/SAP/macOS-enterprise-privileges/wiki/Managing-Privileges#SyslogOptions):

    - **Create a configuration profile** with the `RemoteLogging` key:
        - Set `ServerType` to `syslog`
        - Set `ServerAddress` to the hostname or IP address of your syslog server
        - For syslog, configure the `SyslogOptions` dictionary with:
            - `ServerPort` (Integration default: 5040 TCP)
            - Optional `UseTLS` (boolean, default: false)
            - `LogFacility` (default: 4 - security)
            - `LogSeverity` (default: 6 - informational)
            - `MaximumMessageSize` (default: 480 bytes)

    - **Example configuration profile** (for syslog with TLS):
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

    - **Deploy the configuration profile** to your macOS devices using your MDM solution

3. **Enable the integration in Elastic**:
    - In Kibana navigate to **Management** > **Integrations**
    - In the search top bar, type **SAP Privileges**
    - Select the **SAP Privileges** integration and add it
    - Add all the required integration configuration parameters:
        - Set the correct host and port to match your SAP Privileges configuration
        - Choose TCP or UDP based on your SAP Privileges setup
    - Save the integration

### Validation

To test whether the integration is working correctly:

1. Check that logs are appearing in Kibana under **Discover**
2. Verify that the **SAP Privileges** integration shows data in the **Integrations** view
3. Look for privilege-related events in the logs

## Troubleshooting

### Common issues

- **No logs appearing**: Verify that SAP Privileges is configured to send logs to the correct syslog server and port
- **Connection issues**: Check network connectivity between macOS devices and your syslog server
- **Permission issues**: Ensure the Elastic Agent has appropriate permissions to read logs

For additional troubleshooting, refer to
the [SAP Privileges documentation](https://github.com/SAP/macOS-enterprise-privileges/wiki).

## Performance and scaling

The SAP Privileges integration is designed to be lightweight and has minimal impact on system performance. For optimal
performance:

- Ensure your syslog server is properly sized to handle the log volume from all macOS devices
- Consider using TLS for secure log transmission, but be aware of the additional CPU overhead
- Monitor log volume and adjust `MaximumMessageSize` if needed to balance between log completeness and performance

## Reference

### Logs

This is the `log` dataset.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2026-02-24T14:16:11.133Z",
    "agent": {
        "ephemeral_id": "37b49c9f-269f-4772-8e21-e34c53a3ab83",
        "id": "c78e51b1-8cdb-49ec-b356-12b13b3318c9",
        "name": "elastic-agent-96829",
        "type": "filebeat",
        "version": "9.0.0"
    },
    "data_stream": {
        "dataset": "privileges.log",
        "namespace": "67854",
        "type": "logs"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "elastic_agent": {
        "id": "c78e51b1-8cdb-49ec-b356-12b13b3318c9",
        "snapshot": false,
        "version": "9.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2026-02-24T14:16:11.133Z",
        "dataset": "privileges.log",
        "ingested": "2026-03-17T10:30:47Z",
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
            "address": "172.23.0.3:46671"
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

