# Cisco FTD Integration

This integration is for [Cisco](https://www.cisco.com/c/en/us/support/security/index.html) Firepower Threat Defence (FTD) device's logs. The package processes syslog messages from Cisco Firepower devices.

It includes the following datasets for receiving logs over syslog or read from a file:

- `log` dataset: supports Cisco Firepower Threat Defense (FTD) logs.

## Configuration

Cisco provides a range of Firepower devices, which may have different configuration steps. We recommend users navigate to the device specific configuration page, and search for/go to the "FTD Logging" or "Configure Logging on FTD" page for the specific device.

### Input Types

The integration supports three input types:

1. **TCP Input**: Collects logs via TCP syslog. Configure the FTD device to send syslog messages to the Elastic Agent host on the specified TCP port (default: 9003).

2. **UDP Input**: Collects logs via UDP syslog. Configure the FTD device to send syslog messages to the Elastic Agent host on the specified UDP port (default: 9003). UDP provides lower latency but less reliability than TCP.

3. **Logfile Input**: Reads logs from local log files. Useful for batch processing or when syslog forwarding is not available. Specify the path to the log file(s) on the system.

### Configuration Parameters

- **Host and Port**: Configure the listening host (default: localhost) and port (default: 9003) for TCP/UDP inputs.
- **Timezone**: IANA timezone or offset (e.g., `+0200`) for interpreting syslog timestamps without timezone information (default: UTC).
- **Preserve Original Event**: When enabled, stores the raw syslog message in the `event.original` field.
- **Internal/External Zones**: Configure zone names to help determine network direction. Private CIDR ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) can be used as fallback.
- **Consider Private Networks as Internal**: When enabled, treats private CIDR ranges as internal networks for direction detection (default: true).

## Handling security fields

Due to unknown amount of sub-fields present under the field `cisco.ftd.security`, it is mapped as [`flattened` datatype](https://www.elastic.co/guide/en/elasticsearch/reference/current/flattened.html). This limited certain operations, such as aggregations, to be performed on sub-fields of `cisco.ftd.security`. See [flattened datatype limitations](https://www.elastic.co/guide/en/elasticsearch/reference/current/flattened.html#supported-operations) for more details.

After analyzing more example logs, starting Cisco FTD integration version `2.21.0`, a new field `cisco.ftd.security_event` is added with a known set of fields moved over from `cisco.ftd.security`. With this, users can now perform aggregations on sub-fields of `cisco.ftd.security_event`. In addition to already moved fields, if users desire to add more fields onto `cisco.ftd.security_event` from `cisco.ftd.security`, they can make use of [`@custom` ingest pipeline](https://www.elastic.co/guide/en/elasticsearch/reference/current/ingest.html#pipelines-for-fleet-elastic-agent) that is automatically applied on every document at the end of the existing default pipeline.

To create and [add processors](https://www.elastic.co/guide/en/elasticsearch/reference/current/processors.html) to this `@custom` pipeline for Cisco FTD, users must follow below steps:
1. In Kibana, navigate to `Stack Management -> Ingest Pipelines`.
2. Click `Create Pipeline -> New Pipeline`.
3. Add `Name` as `logs-cisco_ftd.log@custom` and an optional `Description`.
4. Add processors to rename appropriate fields from `cisco.ftd.security` to `cisco.ftd.security_event`.
    - Under `Processors`, click `Add a processor`.
    - Say, you want to move field `threat_name` from `cisco.ftd.security` into `cisco.ftd.security_event`, then add a `Rename` processor with `Field` as `cisco.ftd.security.threat_name` and `Target field` as `cisco.ftd.security_event.threat_name`.
    - Optionally add `Convert` processor to convert the datatype of the renamed field under `cisco.ftd.security_event`.

Now that the fields are available under `cisco.ftd.security_event`, users can perform aggregations of sub-fields under `cisco.ftd.security_event` as desired.

## Logs

### FTD

The `log` dataset collects the Cisco Firepower Threat Defense (FTD) logs.

{{event "log"}}

{{fields "log"}}

## Use Cases

- **Network Security Monitoring**: Monitor firewall events, access control rule matches, and security policy violations
- **Threat Detection**: Detect malware, botnets, and other security threats through file analysis and threat intelligence
- **Compliance Reporting**: Track network access, user authentication, and security events for compliance requirements
- **VPN Monitoring**: Monitor VPN connections, user authentication, and session management
- **SSL/TLS Inspection**: Track SSL/TLS inspection events and policy enforcement
- **URL Filtering**: Monitor web application usage, URL categories, and web filtering policies
- **DNS Monitoring**: Track DNS queries and responses for security analysis
- **Network Flow Analysis**: Analyze network connections, traffic patterns, and bandwidth usage

## Event Types

The integration processes various Cisco FTD event types including:

- **Security Events**: Malware detection, file transfers, threat intelligence matches
- **Access Control Events**: Rule matches, connection allows/blocks, policy decisions
- **VPN Events**: Connection establishment, termination, user authentication (AAA)
- **SSL/TLS Events**: SSL inspection, certificate validation, policy enforcement
- **DNS Events**: DNS queries, responses, and filtering
- **System Events**: Failover, updates, configuration changes
- **File Events**: File uploads/downloads, file analysis results, sandbox status

## Field Mappings

The integration maps Cisco FTD syslog messages to Elastic Common Schema (ECS) fields:

- Network fields: `source.ip`, `destination.ip`, `source.port`, `destination.port`, `network.protocol`, `network.transport`
- Event fields: `event.action`, `event.category`, `event.type`, `event.severity`, `event.code`
- File fields: `file.name`, `file.hash.sha256`, `file.size`, `file.type`
- URL fields: `url.original`, `url.domain`, `url.path`, `url.scheme`
- User fields: `user.name`, `source.user.name`, `destination.user.name`
- Observer fields: `observer.hostname`, `observer.product`, `observer.vendor`, `observer.type`

Cisco-specific fields are prefixed with `cisco.ftd.*` and include:

- `cisco.ftd.message_id`: The Cisco FTD message identifier
- `cisco.ftd.rule_name`: Access Control List rule name
- `cisco.ftd.security_event.*`: Structured security event fields
- `cisco.ftd.security.*`: Flattened security fields (for unknown/variable fields)
- `cisco.ftd.threat_category`: Threat category (virus, botnet, trojan, etc.)
- `cisco.ftd.threat_level`: Threat level (very-low, low, moderate, high, very-high)

## Troubleshooting

### No Data Appearing

- Verify Elastic Agent is running and healthy
- Check network connectivity between FTD device and Elastic Agent
- Verify syslog server configuration on FTD device matches Elastic Agent host/port
- Check firewall rules allow syslog traffic
- Review Elastic Agent logs for connection errors

### Parsing Errors

- Check `event.original` field to see the raw syslog message
- Verify FTD device is sending logs in expected syslog format
- Review Elastic Agent logs for parsing error details
- Ensure FTD device software version is compatible with the integration

### Incorrect Timestamps

- Configure the `tz_offset` parameter in the integration settings
- Use IANA timezone format (e.g., "America/New_York") or offset format (e.g., "+0500")
- Verify FTD device timezone settings match your configuration

### Network Direction Issues

- Configure internal and external zones in the integration settings
- Ensure zone names match exactly with FTD device zone configuration
- Verify `private_is_internal` setting matches your network topology

## Additional Resources

- [Cisco Firepower Threat Defense Documentation](https://www.cisco.com/c/en/us/support/security/firepower-threat-defense/products-installation-and-configuration-guides-list.html)
- [Elastic Integrations Documentation](https://www.elastic.co/guide/en/integrations/index.html)
- [Elastic Agent Documentation](https://www.elastic.co/guide/en/fleet/current/index.html)
