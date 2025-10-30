# Service Info

## Common use cases
- Security monitoring and threat detection from FortiGate firewall logs
- Network traffic analysis and monitoring
- Firewall policy compliance and auditing
- Intrusion detection and prevention system (IPS) event monitoring
- VPN connection monitoring and troubleshooting
- Web filtering and application control monitoring

## Data types collected
- Traffic logs (firewall allow/deny decisions)
- UTM logs (antivirus, web filter, application control, IPS, DNS filter)
- Event logs (system events, HA events, configuration changes)
- Authentication logs (VPN, admin, and user authentication events)

## Compatibility
This integration has been tested against FortiOS versions 13.x. Newer versions are not expected to work but have not been tested.

## Scaling and Performance


# Set Up Instructions

## Vendor prerequisites
- FortiGate firewall with access to configure syslog settings
- Network connectivity between FortiGate and Elastic Agent

## Elastic prerequisites
- Elastic Stack version 8.11.0 or higher

## Vendor set up steps

### Syslog Configuration
1. Configure FortiGate to send syslog messages to the Elastic Agent host
2. For TCP input with reliable syslog mode, ensure framing is set to `rfc6587` (see [Fortigate CLI reference](https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/405620/config-log-syslogd-setting))
3. Configure the appropriate syslog facility and severity levels

## Kibana set up steps
1. In Kibana, navigate to Management > Integrations
2. Search for "Fortinet FortiGate Firewall Logs" and select the integration
3. Click "Add Fortinet FortiGate Firewall Logs"
4. Configure the integration with one of the following input types:
   - **TCP**: Configure listen address and port (default: localhost:9004)
   - **UDP**: Configure listen address and port (default: localhost:9004)
   - **Logfile**: Specify the path to log files
5. Configure optional settings:
   - Internal/External interfaces for network direction mapping
   - Internal networks (defaults to private address ranges)
   - Preserve original event option
6. Assign the integration to an agent policy and save

# Validation Steps
1. Verify logs are being sent from FortiGate by checking the syslog configuration
2. In Kibana, navigate to Discover and search for `data_stream.dataset: "fortinet_fortigate.log"`
3. Verify that events are appearing with recent timestamps
4. Check the dashboards provided by the integration (Management > Dashboards > "Fortinet FortiGate Overview")
5. Generate test traffic on FortiGate (e.g., web browsing, firewall hits) and verify corresponding logs appear in Kibana

# Troubleshooting

## Common Configuration Issues
- **No data collected**: Verify network connectivity between FortiGate and Elastic Agent. Check that the configured listen port matches the port configured on FortiGate.
- **TCP framing issues**: When using TCP with reliable syslog mode, ensure framing is set to `rfc6587` in both FortiGate configuration and the integration settings.

## Ingestion Errors


## API Authentication Errors


## Vendor Resources
- [FortiGate CLI Reference - Syslog Settings](https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/405620/config-log-syslogd-setting)

# Documentation sites
- [Fortinet Documentation Library](https://docs.fortinet.com/)
- [FortiGate Administration Guide](https://docs.fortinet.com/product/fortigate)


