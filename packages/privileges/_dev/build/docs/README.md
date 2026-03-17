# SAP Privileges

The SAP Privileges integration collects and parses privilege-related events
from [SAP Privileges](https://github.com/SAP/macOS-enterprise-privileges) for macOS.
SAP Privileges is a free macOS application designed for modern enterprise environments that gives users temporary
administrator privileges when needed without granting permanent admin rights.

## Overview

### Compatibility

This module has been tested against SAP Privileges Version 2.x and should work with all versions.

### How it works

The integration collects privilege-related events from SAP Privileges and parses them into structured logs. It monitors privilege escalation events, renewal notifications, and privilege expiration events to provide visibility into administrator privilege usage across macOS devices in enterprise environments.

## What data does this integration collect?

The SAP Privileges integration collects log data from SAP Privileges application on macOS devices. The integration supports the following use cases:

- Monitor privilege escalation events
- Track privilege renewal and expiration
- Audit administrator privilege usage
- Identify potential security risks related to privilege management

## What do I need to use this integration?

- Elastic Agent must be installed on your macOS devices.
- SAP Privileges application must be installed and configured to send logs to your syslog server.
- Appropriate permissions to configure SAP Privileges and deploy configuration profiles via MDM.

For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## How do I deploy this integration?

### Onboard and configure

1. **Install and configure SAP Privileges**:
   - Install SAP Privileges on your macOS devices
   - Configure SAP Privileges to send logs to your Elastic stack

2. **Configure SAP Privileges to send logs**:
   Product specific manual can be found [here](https://github.com/SAP/macOS-enterprise-privileges/wiki/Managing-Privileges#SyslogOptions):

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

For additional troubleshooting, refer to the [SAP Privileges documentation](https://github.com/SAP/macOS-enterprise-privileges/wiki).

## Performance and scaling

The SAP Privileges integration is designed to be lightweight and has minimal impact on system performance. For optimal performance:

- Ensure your syslog server is properly sized to handle the log volume from all macOS devices
- Consider using TLS for secure log transmission, but be aware of the additional CPU overhead
- Monitor log volume and adjust `MaximumMessageSize` if needed to balance between log completeness and performance

## Reference

### Logs

This is the `log` dataset.

{{event "log"}}

{{fields "log"}}
