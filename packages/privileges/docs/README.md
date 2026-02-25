# SAP Privileges

The SAP Privileges integration collects and parses privilege management events from [SAP Privileges](https://github.com/SAP/macOS-enterprise-privileges) for macOS. SAP Privileges is a free macOS application designed for modern enterprise environments that gives users temporary administrator privileges when needed without granting permanent admin rights.

## Data streams

The SAP Privileges integration collects the following event types: `log`.

## Compatibility

This integration has been tested with SAP Privileges 2.x and should work with all versions.

## Requirements

- Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).
- SAP Privileges must be installed on the macOS devices you want to monitor.

## Setup

### Configure SAP Privileges to send Syslog

To configure SAP Privileges to send logs to your Elastic Agent:

1. **Create a configuration profile** (mobileconfig file) with remote logging settings:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadContent</key>
			<dict>
				<key>corp.sap.privileges</key>
				<dict>
					<key>Forced</key>
					<array>
						<dict>
							<key>mcx_preference_settings</key>
							<dict>
								<key>RemoteLogging</key>
								<dict>
									<key>ServerType</key>
									<string>syslog</string>
									<key>ServerAddress</key>
									<string>YOUR_AGENT_IP_OR_HOSTNAME</string>
									<key>SyslogOptions</key>
									<dict>
										<key>ServerPort</key>
										<integer>514</integer>
										<key>UseTLS</key>
										<false/>
										<key>LogFacility</key>
										<integer>4</integer>
										<key>LogSeverity</key>
										<integer>6</integer>
										<key>MaximumMessageSize</key>
										<integer>480</integer>
									</dict>
								</dict>
							</dict>
						</dict>
					</array>
				</dict>
			</dict>
			<key>PayloadDescription</key>
			<string/>
			<key>PayloadDisplayName</key>
			<string>Privileges configuration</string>
			<key>PayloadEnabled</key>
			<true/>
			<key>PayloadIdentifier</key>
			<string>com.apple.ManagedClient.preferences.36132147-235E-4663-ADA8-2664C67C4DD2</string>
			<key>PayloadOrganization</key>
			<string>SAP SE</string>
			<key>PayloadType</key>
			<string>com.apple.ManagedClient.preferences</string>
			<key>PayloadUUID</key>
			<string>36132147-235E-4663-ADA8-2664C67C4DD2</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Configures the Privileges app.</string>
	<key>PayloadDisplayName</key>
	<string>Privileges configuration</string>
	<key>PayloadEnabled</key>
	<true/>
	<key>PayloadIdentifier</key>
	<string>CF401A42-35CA-4DA6-9123-5A49C87ECB5A</string>
	<key>PayloadOrganization</key>
	<string>SAP SE</string>
	<key>PayloadRemovalDisallowed</key>
	<true/>
	<key>PayloadScope</key>
	<string>System</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>50870D16-7AAD-478B-BFFE-BED09499F7E0</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
```

2. **Replace `YOUR_AGENT_IP_OR_HOSTNAME`** with the IP address or hostname of your Elastic Agent or load balancer.

3. **Adjust the port** (`ServerPort`) to match the port configured in your Elastic Agent integration.

4. **Deploy the configuration profile** to your macOS devices using your MDM solution (e.g., Jamf, Kandji, Mosyle).

### Enable the integration in Elastic

1. In Kibana, navigate to **Management** > **Integrations**.
2. In the search bar, type **SAP Privileges** or **Privileges**.
3. Select the **SAP Privileges** integration and add it.
4. Add all the required integration configuration parameters:
   - Set the correct **host** (IP or hostname)
   - Set the correct **port** (must match the port in the configuration profile)
   - Choose **TCP** or **UDP** protocol (must match the configuration profile)
5. Save the integration.

## Log samples

Below are sample logs from SAP Privileges:

### Privilege Grant Logs

```
<134>2025-01-23T09:49:10.000+05:00 SRV-MAC-001 Privileges: User john.doe granted admin privileges for 1 hour
```

### Privilege Revoke Logs

```
<134>2025-01-23T10:49:10.000+05:00 SRV-MAC-001 Privileges: User john.doe admin privileges revoked
```

### Authentication Logs

```
<134>2025-01-23T11:32:57.000+05:00 SRV-MAC-001 Privileges: User john.doe authenticated successfully
```

## Logs

This is the `log` dataset.

An example event for `log` looks as follows:

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
| sap_privileges.action | The action performed (grant, revoke, authenticate, etc.) | keyword |
| sap_privileges.duration | Duration of granted privileges | keyword |
| sap_privileges.user.name | Name of the user | keyword |
| sap_privileges.user.id | User ID | keyword |
| sap_privileges.outcome | Outcome of the operation (success, failure) | keyword |
| sap_privileges.reason | Reason provided by user | keyword |

## Additional Resources

- [SAP Privileges GitHub Repository](https://github.com/SAP/macOS-enterprise-privileges)
- [SAP Privileges Documentation](https://github.com/SAP/macOS-enterprise-privileges#documentation)
- [Example Configuration Profiles](https://github.com/SAP/macOS-enterprise-privileges/tree/main/application_management/example_profiles)
