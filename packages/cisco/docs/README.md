# Cisco Integration

This integration is for Cisco network device's logs. It includes the following
datasets for receiving logs over syslog or read from a file:

- `asa` dataset: supports Cisco ASA firewall logs.
- `ftd` dataset: supports Cisco Firepower Threat Defense logs.
- `ios` dataset: supports Cisco IOS router and switch logs.

## Compatibility

## Logs

### ASA

The `asa` dataset collects the Cisco firewall logs.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cisco.asa.connection_id | Unique identifier for a flow. | keyword |
| cisco.asa.connection_type | The VPN connection type | keyword |
| cisco.asa.dap_records | The assigned DAP records | keyword |
| cisco.asa.destination_interface | Destination interface for the flow or event. | keyword |
| cisco.asa.destination_username | Name of the user that is the destination for this event. | keyword |
| cisco.asa.icmp_code | ICMP code. | short |
| cisco.asa.icmp_type | ICMP type. | short |
| cisco.asa.mapped_destination_ip | The translated destination IP address. | ip |
| cisco.asa.mapped_destination_port | The translated destination port. | long |
| cisco.asa.mapped_source_ip | The translated source IP address. | ip |
| cisco.asa.mapped_source_port | The translated source port. | long |
| cisco.asa.message_id | The Cisco ASA message identifier. | keyword |
| cisco.asa.rule_name | Name of the Access Control List rule that matched this event. | keyword |
| cisco.asa.source_interface | Source interface for the flow or event. | keyword |
| cisco.asa.source_username | Name of the user that is the source for this event. | keyword |
| cisco.asa.suffix | Optional suffix after %ASA identifier. | keyword |
| cisco.asa.threat_category | Category for the malware / botnet traffic. For example: virus, botnet, trojan, etc. | keyword |
| cisco.asa.threat_level | Threat level for malware / botnet traffic. One of very-low, low, moderate, high or very-high. | keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| event.category | Event category (e.g. database) | keyword |
| event.code | Identification code for this event | keyword |
| event.created | The date/time when the event was first read by an agent, or by your pipeline. | date |
| event.duration | Duration of the event in nanoseconds. | long |
| event.end | The date when the event ended or when the activity was last observed. | keyword |
| event.kind | Event kind (e.g. event) | keyword |
| event.provider | Source of the event (e.g. Server) | keyword |
| event.start | The date when the event started or when the activity was first observed. | date |
| event.timezone | Time zone information | keyword |
| event.type | Event severity (e.g. info, error) | keyword |
| labels | Custom key/value pairs. Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword. Example:   application: foo-bar   env: production | object |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. | text |


### FTD

The `ftd` dataset collects the Firepower Threat Defense logs.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cisco.ftd.connection_id | Unique identifier for a flow. | keyword |
| cisco.ftd.connection_type | The VPN connection type | keyword |
| cisco.ftd.dap_records | The assigned DAP records | keyword |
| cisco.ftd.destination_interface | Destination interface for the flow or event. | keyword |
| cisco.ftd.destination_username | Name of the user that is the destination for this event. | keyword |
| cisco.ftd.icmp_code | ICMP code. | short |
| cisco.ftd.icmp_type | ICMP type. | short |
| cisco.ftd.mapped_destination_ip | The translated destination IP address. Use ECS destination.nat.ip. | ip |
| cisco.ftd.mapped_destination_port | The translated destination port. Use ECS destination.nat.port. | long |
| cisco.ftd.mapped_source_ip | The translated source IP address. Use ECS source.nat.ip. | ip |
| cisco.ftd.mapped_source_port | The translated source port. Use ECS source.nat.port. | long |
| cisco.ftd.message_id | The Cisco FTD message identifier. | keyword |
| cisco.ftd.rule_name | Name of the Access Control List rule that matched this event. | keyword |
| cisco.ftd.security | Raw fields for Security Events. | object |
| cisco.ftd.source_interface | Source interface for the flow or event. | keyword |
| cisco.ftd.source_username | Name of the user that is the source for this event. | keyword |
| cisco.ftd.suffix | Optional suffix after %FTD identifier. | keyword |
| cisco.ftd.threat_category | Category for the malware / botnet traffic. For example: virus, botnet, trojan, etc. | keyword |
| cisco.ftd.threat_level | Threat level for malware / botnet traffic. One of very-low, low, moderate, high or very-high. | keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| event.category | Event category (e.g. database) | keyword |
| event.code | Identification code for this event | keyword |
| event.created | The date/time when the event was first read by an agent, or by your pipeline. | date |
| event.duration | Duration of the event in nanoseconds. | long |
| event.end | The date when the event ended or when the activity was last observed. | keyword |
| event.kind | Event kind (e.g. event) | keyword |
| event.provider | Source of the event (e.g. Server) | keyword |
| event.start | The date when the event started or when the activity was first observed. | date |
| event.timezone | Time zone information | keyword |
| event.type | Event severity (e.g. info, error) | keyword |
| labels | Custom key/value pairs. Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword. Example:   application: foo-bar   env: production | object |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. | text |


### IOS

The `ios` dataset collects the Cisco IOS router and switch logs.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. example: '2016-05-23T08:05:34.853Z' | date |
| cisco.ios.access_list | Name of the IP access list. | keyword |
| cisco.ios.facility | The facility to which the message refers (for example, SNMP, SYS, and so forth). A facility can be a hardware device, a protocol, or a module of the system software. It denotes the source or the cause of the system message. | keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| event.category | Event category (e.g. database) | keyword |
| event.code | Identification code for this event | keyword |
| event.created | Date/time when the event was first read by an agent, or by your pipeline. | date |
| event.duration | Duration of the event in nanoseconds. | long |
| event.end | The date when the event ended or when the activity was last observed. | keyword |
| event.kind | Event kind (e.g. event) | keyword |
| event.provider | Source of the event (e.g. Server) | keyword |
| event.start | The date when the event started or when the activity was first observed. | date |
| event.timezone | Time zone information | keyword |
| event.type | Event severity (e.g. info, error) | keyword |
| labels | Custom key/value pairs. Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword. Example:   application: foo-bar   env: production | object |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. | text |
