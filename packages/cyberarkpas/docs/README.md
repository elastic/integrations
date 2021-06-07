# Cyberark Privileged Access Security

The Cyberark Privileged Access Security integration collects audit logs from Cyberark's Vault server.

## Audit

The `audit` dataset receives Vault Audit logs for User and Safe activities over the syslog protocol.

### Vault Configuration

Follow the steps under [Security Information and Event Management (SIEM) Applications](https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/PASIMP/DV-Integrating-with-SIEM-Applications.htm) documentation to setup the integration:

- Copy the [elastic-json-v1.0.xsl](https://raw.githubusercontent.com/elastic/beats/master/x-pack/filebeat/module/cyberarkpas/_meta/assets/elastic-json-v1.0.xsl) XSL Translator file to
the `Server\Syslog` folder.

- Sample syslog configuration for `DBPARM.ini`:

```ini
[SYSLOG]
UseLegacySyslogFormat=No
SyslogTranslatorFile=Syslog\elastic-json-v1.0.xsl
SyslogServerIP=<INSERT FILEBEAT IP HERE>
SyslogServerPort=<INSERT FILEBEAT PORT HERE>
SyslogServerProtocol=TCP
```

For proper timestamping of events, it's recommended to use the newer RFC5424 Syslog format
(`UseLegacySyslogFormat=No`). To avoid event loss, use `TCP` or `TLS` protocols instead of `UDP`.

### Example event

An example event for `audit` looks as following:

```$json
{
    "@timestamp": "2021-03-04T17:27:14.000Z",
    "cyberarkpas": {
        "audit": {
            "action": "Logon",
            "desc": "Logon",
            "iso_timestamp": "2021-03-04T17:27:14Z",
            "issuer": "PVWAGWUser",
            "message": "Logon",
            "rfc5424": true,
            "severity": "Info",
            "station": "10.0.1.20",
            "timestamp": "Mar 04 09:27:14"
        }
    },
    "event": {
        "action": "authentication_success",
        "category": [
            "authentication",
            "session"
        ],
        "code": "7",
        "kind": "event",
        "module": "cyberarkpas",
        "outcome": "success",
        "severity": 2,
        "timezone": "-02:00",
        "type": [
            "start"
        ]
    },
    "host": {
        "name": "VAULT"
    },
    "log": {
        "syslog": {
            "priority": 5
        }
    },
    "observer": {
        "hostname": "VAULT",
        "product": "Vault",
        "vendor": "Cyber-Ark",
        "version": "11.7.0000"
    },
    "related": {
        "ip": [
            "10.0.1.20"
        ],
        "user": [
            "PVWAGWUser"
        ]
    },
    "source": {
        "address": "10.0.1.20",
        "ip": "10.0.1.20"
    },
    "tags": [
        "cyberarkpas.audit",
        "forwarded"
    ],
    "user": {
        "name": "PVWAGWUser"
    }
}
```

**Exported fields**

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cyberarkpas.audit.action | A description of the audit record. | keyword |
| cyberarkpas.audit.ca_properties.address |  | keyword |
| cyberarkpas.audit.ca_properties.cpm_disabled |  | keyword |
| cyberarkpas.audit.ca_properties.cpm_error_details |  | keyword |
| cyberarkpas.audit.ca_properties.cpm_status |  | keyword |
| cyberarkpas.audit.ca_properties.creation_method |  | keyword |
| cyberarkpas.audit.ca_properties.customer |  | keyword |
| cyberarkpas.audit.ca_properties.database |  | keyword |
| cyberarkpas.audit.ca_properties.device_type |  | keyword |
| cyberarkpas.audit.ca_properties.dual_account_status |  | keyword |
| cyberarkpas.audit.ca_properties.group_name |  | keyword |
| cyberarkpas.audit.ca_properties.in_process |  | keyword |
| cyberarkpas.audit.ca_properties.index |  | keyword |
| cyberarkpas.audit.ca_properties.last_fail_date |  | keyword |
| cyberarkpas.audit.ca_properties.last_success_change |  | keyword |
| cyberarkpas.audit.ca_properties.last_success_reconciliation |  | keyword |
| cyberarkpas.audit.ca_properties.last_success_verification |  | keyword |
| cyberarkpas.audit.ca_properties.last_task |  | keyword |
| cyberarkpas.audit.ca_properties.logon_domain |  | keyword |
| cyberarkpas.audit.ca_properties.other |  | flattened |
| cyberarkpas.audit.ca_properties.policy_id |  | keyword |
| cyberarkpas.audit.ca_properties.port |  | keyword |
| cyberarkpas.audit.ca_properties.privcloud |  | keyword |
| cyberarkpas.audit.ca_properties.reset_immediately |  | keyword |
| cyberarkpas.audit.ca_properties.retries_count |  | keyword |
| cyberarkpas.audit.ca_properties.sequence_id |  | keyword |
| cyberarkpas.audit.ca_properties.tags |  | keyword |
| cyberarkpas.audit.ca_properties.user_dn |  | keyword |
| cyberarkpas.audit.ca_properties.user_name |  | keyword |
| cyberarkpas.audit.ca_properties.virtual_username |  | keyword |
| cyberarkpas.audit.category | The category name (for category-related operations). | keyword |
| cyberarkpas.audit.desc | A static value that displays a description of the audit codes. | keyword |
| cyberarkpas.audit.extra_details.ad_process_id |  | keyword |
| cyberarkpas.audit.extra_details.ad_process_name |  | keyword |
| cyberarkpas.audit.extra_details.application_type |  | keyword |
| cyberarkpas.audit.extra_details.command |  | keyword |
| cyberarkpas.audit.extra_details.connection_component_id |  | keyword |
| cyberarkpas.audit.extra_details.dst_host |  | keyword |
| cyberarkpas.audit.extra_details.logon_account |  | keyword |
| cyberarkpas.audit.extra_details.managed_account |  | keyword |
| cyberarkpas.audit.extra_details.other |  | flattened |
| cyberarkpas.audit.extra_details.process_id |  | keyword |
| cyberarkpas.audit.extra_details.process_name |  | keyword |
| cyberarkpas.audit.extra_details.protocol |  | keyword |
| cyberarkpas.audit.extra_details.psmid |  | keyword |
| cyberarkpas.audit.extra_details.session_duration |  | keyword |
| cyberarkpas.audit.extra_details.session_id |  | keyword |
| cyberarkpas.audit.extra_details.src_host |  | keyword |
| cyberarkpas.audit.extra_details.username |  | keyword |
| cyberarkpas.audit.file | The name of the target file. | keyword |
| cyberarkpas.audit.gateway_station | The IP of the web application machine (PVWA). | ip |
| cyberarkpas.audit.hostname | The hostname, in upper case. | keyword |
| cyberarkpas.audit.iso_timestamp | The timestamp, in ISO Timestamp format (RFC 3339). | date |
| cyberarkpas.audit.issuer | The Vault user who wrote the audit. This is usually the user who performed the operation. | keyword |
| cyberarkpas.audit.location | The target Location (for Location operations). | keyword |
| cyberarkpas.audit.message | A description of the audit records (same information as in the Desc field). | keyword |
| cyberarkpas.audit.message_id | The code ID of the audit records. | keyword |
| cyberarkpas.audit.product | A static value that represents the product. | keyword |
| cyberarkpas.audit.pvwa_details | Specific details of the PVWA audit records. | flattened |
| cyberarkpas.audit.raw | Raw XML for the original audit record. Only present when XSLT file has debugging enabled. | keyword |
| cyberarkpas.audit.reason | The reason entered by the user. | text |
| cyberarkpas.audit.rfc5424 | Whether the syslog format complies with RFC5424. | boolean |
| cyberarkpas.audit.safe | The name of the target Safe. | keyword |
| cyberarkpas.audit.severity | The severity of the audit records. | keyword |
| cyberarkpas.audit.source_user | The name of the Vault user who performed the operation. | keyword |
| cyberarkpas.audit.station | The IP from where the operation was performed. For PVWA sessions, this will be the real client machine IP. | ip |
| cyberarkpas.audit.target_user | The name of the Vault user on which the operation was performed. | keyword |
| cyberarkpas.audit.timestamp | The timestamp, in MMM DD HH:MM:SS format. | keyword |
| cyberarkpas.audit.vendor | A static value that represents the vendor. | keyword |
| cyberarkpas.audit.version | A static value that represents the version of the Vault. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.domain | Destination domain. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.user.name | Short name or login of the user. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` < `event.created` < `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, consider using the wildcard data type. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 * facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| network.application | A name given to an application level protocol. This can be arbitrarily assigned for things like microservices, but also apply to things like skype, icq, facebook, twitter. This would be used in situations where the vendor or service can be decoded such as from the source/dest IP owners, ports, or wire format. The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   * ingress   * egress   * inbound   * outbound   * internal   * external   * unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| observer.hostname | Hostname of the observer. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| observer.version | Observer version. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.pid | Process id. | long |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names seen on your event. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.user.name | Short name or login of the user. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |

