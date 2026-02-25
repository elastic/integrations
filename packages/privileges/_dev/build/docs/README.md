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

Below are the sample logs of the respective category.

### Audit Logs

```
<134>2025-01-23T13:00:00.000+05:00 SRV-MAC-001 Privileges: User john.doe renewed admin privileges for 1 hour
<134>2025-01-23T13:05:00.000+05:00 SRV-MAC-001 Privileges: User jane.smith privilege renewal notification sent
```

## Logs

This is the `log` dataset.

{{event "log"}}

{{fields "log"}}
