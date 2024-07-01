# Cisco FTD Integration

This integration is for [Cisco](https://www.cisco.com/c/en/us/support/security/index.html) Firepower Threat Defence (FTD) device's logs. The package processes syslog messages from Cisco Firepower devices 

It includes the following datasets for receiving logs over syslog or read from a file:

- `log` dataset: supports Cisco Firepower Threat Defense (FTD) logs.

## Configuration

Cisco provides a range of Firepower devices, which may have different configuration steps. We recommend users navigate to the device specific configuration page, and search for/go to the "FTD Logging" or "Configure Logging on FTD" page for the specific device.

## Handling security fields

Due to unknown amount of sub-fields present under the field `cisco.ftd.security`, it is mapped as [`flattened` datatype](https://www.elastic.co/guide/en/elasticsearch/reference/current/flattened.html). This limited certain operations, such as aggregations, to be performed on sub-fields of `cisco.ftd.security`. See [flattened dataype limitations](https://www.elastic.co/guide/en/elasticsearch/reference/current/flattened.html#supported-operations) for more details.

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

An example event for `log` looks as following:

```json
{
    "@timestamp": "2019-08-16T09:39:02.000Z",
    "agent": {
        "ephemeral_id": "1ab84bcb-b57f-4f6a-bb15-6534c4ceba57",
        "id": "003c2ae5-ffc1-4a61-a309-b9d59a743dda",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.3"
    },
    "cisco": {
        "ftd": {
            "rule_name": "malware-and-file-policy",
            "security": {
                "file_storage_status": "Not Stored (Disposition Was Pending)",
                "threat_name": "Win.Ransomware.Eicar::95.sbx.tg"
            },
            "security_event": {
                "application_protocol": "HTTP",
                "client": "cURL",
                "dst_ip": "81.2.69.144",
                "dst_port": 80,
                "file_action": "Malware Cloud Lookup",
                "file_direction": "Download",
                "file_name": "eicar_com.zip",
                "file_policy": "malware-and-file-policy",
                "file_sandbox_status": "File Size Is Too Small",
                "file_sha256": "2546dcffc5ad854d4ddc64fbf056871cd5a00f2471cb7a5bfd4ac23b6e9eedad",
                "file_size": 184,
                "file_type": "ZIP",
                "first_packet_second": "2019-08-16T09:39:02Z",
                "protocol": "tcp",
                "sha_disposition": "Unavailable",
                "spero_disposition": "Spero detection not performed on file",
                "src_ip": "10.0.1.20",
                "src_port": 46004,
                "uri": "http://www.eicar.org/download/eicar_com.zip",
                "user": "No Authentication Required"
            },
            "threat_category": "Win.Ransomware.Eicar::95.sbx.tg"
        }
    },
    "data_stream": {
        "dataset": "cisco_ftd.log",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "address": "81.2.69.144",
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.144",
        "port": 80
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "003c2ae5-ffc1-4a61-a309-b9d59a743dda",
        "snapshot": false,
        "version": "8.10.3"
    },
    "event": {
        "action": "malware-detected",
        "agent_id_status": "verified",
        "category": [
            "malware",
            "file"
        ],
        "code": "430005",
        "dataset": "cisco_ftd.log",
        "ingested": "2023-11-14T06:10:15Z",
        "kind": "event",
        "original": "2019-08-16T09:39:03Z firepower  %FTD-1-430005: SrcIP: 10.0.1.20, DstIP: 81.2.69.144, SrcPort: 46004, DstPort: 80, Protocol: tcp, FileDirection: Download, FileAction: Malware Cloud Lookup, FileSHA256: 2546dcffc5ad854d4ddc64fbf056871cd5a00f2471cb7a5bfd4ac23b6e9eedad, SHA_Disposition: Unavailable, SperoDisposition: Spero detection not performed on file, ThreatName: Win.Ransomware.Eicar::95.sbx.tg, FileName: eicar_com.zip, FileType: ZIP, FileSize: 184, ApplicationProtocol: HTTP, Client: cURL, User: No Authentication Required, FirstPacketSecond: 2019-08-16T09:39:02Z, FilePolicy: malware-and-file-policy, FileStorageStatus: Not Stored (Disposition Was Pending), FileSandboxStatus: File Size Is Too Small, URI: http://www.eicar.org/download/eicar_com.zip",
        "severity": 1,
        "start": "2019-08-16T09:39:02Z",
        "timezone": "UTC",
        "type": [
            "info"
        ]
    },
    "file": {
        "hash": {
            "sha256": "2546dcffc5ad854d4ddc64fbf056871cd5a00f2471cb7a5bfd4ac23b6e9eedad"
        },
        "name": "eicar_com.zip",
        "size": 184
    },
    "host": {
        "hostname": "firepower"
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "level": "alert",
        "source": {
            "address": "192.168.160.4:39732"
        }
    },
    "network": {
        "application": "curl",
        "community_id": "1:jk2uwniJ2oCG0t73HeZ9w8gtA8E=",
        "direction": "outbound",
        "iana_number": "6",
        "protocol": "http",
        "transport": "tcp"
    },
    "observer": {
        "hostname": "firepower",
        "product": "ftd",
        "type": "idps",
        "vendor": "Cisco"
    },
    "related": {
        "hash": [
            "2546dcffc5ad854d4ddc64fbf056871cd5a00f2471cb7a5bfd4ac23b6e9eedad"
        ],
        "hosts": [
            "firepower"
        ],
        "ip": [
            "10.0.1.20",
            "81.2.69.144"
        ]
    },
    "rule": {
        "ruleset": "malware-and-file-policy"
    },
    "source": {
        "address": "10.0.1.20",
        "ip": "10.0.1.20",
        "port": 46004
    },
    "tags": [
        "preserve_original_event",
        "private_is_internal",
        "cisco-ftd",
        "forwarded"
    ],
    "url": {
        "domain": "www.eicar.org",
        "extension": "zip",
        "original": "http://www.eicar.org/download/eicar_com.zip",
        "path": "/download/eicar_com.zip",
        "scheme": "http"
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cisco.ftd.aaa_type | The AAA operation type. One of authentication, authorization, or accounting. | keyword |
| cisco.ftd.assigned_ip | The IP address assigned to a VPN client successfully connecting | ip |
| cisco.ftd.burst.avg_rate | The current average burst rate seen | keyword |
| cisco.ftd.burst.configured_avg_rate | The current configured average burst rate allowed | keyword |
| cisco.ftd.burst.configured_rate | The current configured burst rate | keyword |
| cisco.ftd.burst.cumulative_count | The total count of burst rate hits since the object was created or cleared | keyword |
| cisco.ftd.burst.current_rate | The current burst rate seen | keyword |
| cisco.ftd.burst.id | The related rate ID for burst warnings | keyword |
| cisco.ftd.burst.object | The related object for burst warnings | keyword |
| cisco.ftd.command_line_arguments | The command line arguments logged by the local audit log | keyword |
| cisco.ftd.connection_id | Unique identifier for a flow. | keyword |
| cisco.ftd.connection_type | The VPN connection type | keyword |
| cisco.ftd.dap_records | The assigned DAP records | keyword |
| cisco.ftd.destination_interface | Destination interface for the flow or event. | keyword |
| cisco.ftd.destination_user_or_sgt | The destination user or security group tag. | keyword |
| cisco.ftd.destination_username | Name of the user that is the destination for this event. | keyword |
| cisco.ftd.icmp_code | ICMP code. | short |
| cisco.ftd.icmp_type | ICMP type. | short |
| cisco.ftd.mapped_destination_host |  | keyword |
| cisco.ftd.mapped_destination_ip | The translated destination IP address. | ip |
| cisco.ftd.mapped_destination_port | The translated destination port. | long |
| cisco.ftd.mapped_source_host |  | keyword |
| cisco.ftd.mapped_source_ip | The translated source IP address. | ip |
| cisco.ftd.mapped_source_port | The translated source port. | long |
| cisco.ftd.message_id | The Cisco FTD message identifier. | keyword |
| cisco.ftd.privilege.new | When a users privilege is changed this is the new value | keyword |
| cisco.ftd.privilege.old | When a users privilege is changed this is the old value | keyword |
| cisco.ftd.rule_name | Name of the Access Control List rule that matched this event. | keyword |
| cisco.ftd.security | Cisco FTD security event fields. | flattened |
| cisco.ftd.security_event.ac_policy |  | keyword |
| cisco.ftd.security_event.access_control_rule_action |  | keyword |
| cisco.ftd.security_event.access_control_rule_name |  | keyword |
| cisco.ftd.security_event.access_control_rule_reason |  | keyword |
| cisco.ftd.security_event.application_protocol |  | keyword |
| cisco.ftd.security_event.client |  | keyword |
| cisco.ftd.security_event.client_version |  | keyword |
| cisco.ftd.security_event.connection_duration |  | integer |
| cisco.ftd.security_event.dns_query |  | keyword |
| cisco.ftd.security_event.dns_record_type |  | keyword |
| cisco.ftd.security_event.dns_response_type |  | keyword |
| cisco.ftd.security_event.dns_ttl |  | integer |
| cisco.ftd.security_event.dst_ip |  | ip |
| cisco.ftd.security_event.dst_port |  | integer |
| cisco.ftd.security_event.egress_interface |  | keyword |
| cisco.ftd.security_event.egress_zone |  | keyword |
| cisco.ftd.security_event.file_action |  | keyword |
| cisco.ftd.security_event.file_count |  | integer |
| cisco.ftd.security_event.file_direction |  | keyword |
| cisco.ftd.security_event.file_name |  | keyword |
| cisco.ftd.security_event.file_policy |  | keyword |
| cisco.ftd.security_event.file_sandbox_status |  | keyword |
| cisco.ftd.security_event.file_sha256 |  | keyword |
| cisco.ftd.security_event.file_size |  | integer |
| cisco.ftd.security_event.file_type |  | keyword |
| cisco.ftd.security_event.first_packet_second |  | date |
| cisco.ftd.security_event.http_referer |  | keyword |
| cisco.ftd.security_event.http_response |  | integer |
| cisco.ftd.security_event.icmp_code |  | keyword |
| cisco.ftd.security_event.icmp_type |  | keyword |
| cisco.ftd.security_event.ingress_interface |  | keyword |
| cisco.ftd.security_event.ingress_zone |  | keyword |
| cisco.ftd.security_event.initiator_bytes |  | long |
| cisco.ftd.security_event.initiator_packets |  | integer |
| cisco.ftd.security_event.nap_policy |  | keyword |
| cisco.ftd.security_event.prefilter_policy |  | keyword |
| cisco.ftd.security_event.protocol |  | keyword |
| cisco.ftd.security_event.referenced_host |  | keyword |
| cisco.ftd.security_event.responder_bytes |  | long |
| cisco.ftd.security_event.responder_packets |  | integer |
| cisco.ftd.security_event.sha_disposition |  | keyword |
| cisco.ftd.security_event.spero_disposition |  | keyword |
| cisco.ftd.security_event.src_ip |  | ip |
| cisco.ftd.security_event.src_port |  | integer |
| cisco.ftd.security_event.ssl_actual_action |  | keyword |
| cisco.ftd.security_event.ssl_certificate |  | keyword |
| cisco.ftd.security_event.ssl_expected_action |  | keyword |
| cisco.ftd.security_event.ssl_flow_status |  | keyword |
| cisco.ftd.security_event.ssl_policy |  | keyword |
| cisco.ftd.security_event.ssl_rule_name |  | keyword |
| cisco.ftd.security_event.ssl_server_cert_status |  | keyword |
| cisco.ftd.security_event.ssl_server_name |  | keyword |
| cisco.ftd.security_event.ssl_session_id |  | keyword |
| cisco.ftd.security_event.ssl_ticket_id |  | keyword |
| cisco.ftd.security_event.ssl_version |  | keyword |
| cisco.ftd.security_event.sslurl_category |  | keyword |
| cisco.ftd.security_event.tunnel_or_prefilter_rule |  | keyword |
| cisco.ftd.security_event.uri |  | keyword |
| cisco.ftd.security_event.url |  | keyword |
| cisco.ftd.security_event.url_category |  | keyword |
| cisco.ftd.security_event.url_reputation |  | keyword |
| cisco.ftd.security_event.user |  | keyword |
| cisco.ftd.security_event.user_agent |  | keyword |
| cisco.ftd.security_event.web_application |  | keyword |
| cisco.ftd.session_type | Session type (for example, IPsec or UDP). | keyword |
| cisco.ftd.source_interface | Source interface for the flow or event. | keyword |
| cisco.ftd.source_user_or_sgt | The source user or security group tag. | keyword |
| cisco.ftd.source_username | Name of the user that is the source for this event. | keyword |
| cisco.ftd.suffix | Optional suffix after %FTD identifier. | keyword |
| cisco.ftd.termination_user | AAA name of user requesting termination | keyword |
| cisco.ftd.threat_category | Category for the malware / botnet traffic. For example: virus, botnet, trojan, etc. | keyword |
| cisco.ftd.threat_level | Threat level for malware / botnet traffic. One of very-low, low, moderate, high or very-high. | keyword |
| cisco.ftd.translation_type | The translation type | keyword |
| cisco.ftd.tunnel_type | SA type (remote access or L2L) | keyword |
| cisco.ftd.username |  | keyword |
| cisco.ftd.webvpn.group_name | The WebVPN group name the user belongs to | keyword |
| client.address | Some event client addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| client.domain | The domain name of the client system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| client.user.name | Short name or login of the user. | keyword |
| client.user.name.text | Multi-field of `client.user.name`. | match_only_text |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_code | Two-letter code representing continent's name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| destination.geo.postal_code | Postal code associated with the location. Values appropriate for this field may also be known as a postcode or ZIP code and will vary widely from country to country. | keyword |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.geo.timezone | The time zone of the location, such as IANA time zone name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.nat.ip | Translated ip of destination based NAT sessions (e.g. internet to private DMZ) Typically used with load balancers, firewalls, or routers. | ip |
| destination.nat.port | Port the source session is translated to by NAT Device. Typically used with load balancers, firewalls, or routers. | long |
| destination.packets | Packets sent from the destination to the source. | long |
| destination.port | Port of the destination. | long |
| destination.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| destination.user.email | User email address. | keyword |
| destination.user.name | Short name or login of the user. | keyword |
| destination.user.name.text | Multi-field of `destination.user.name`. | match_only_text |
| device.manufacturer | The vendor name of the device manufacturer. | keyword |
| device.model.name | The human readable marketing name of the device model. | keyword |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | keyword |
| dns.question.registered_domain | The highest registered domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| dns.question.subdomain | The subdomain is all of the labels under the registered_domain. If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| dns.question.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| dns.question.type | The type of record being queried. | keyword |
| dns.response_code | The DNS response code. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If `event.start` and `event.end` are known this value should be the difference between the end and start time. | long |
| event.end | `event.end` contains the date when the event ended or when the activity was last observed. | date |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.start | `event.start` contains the date when the event started or when the activity was first observed. | date |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.full | Operating system name, including the version or code name. | keyword |
| host.os.full.text | Multi-field of `host.os.full`. | match_only_text |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. If the OS you're dealing with is not listed as an expected value, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.status_code | HTTP response status code. | long |
| input.type | Input type. | keyword |
| labels | Custom key/value pairs. Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword. Example: `docker` and `k8s` labels. | object |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| log.syslog.facility.code | The Syslog numeric facility of the log event, if available. According to RFCs 5424 and 3164, this value should be an integer between 0 and 23. | long |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| log.syslog.severity.code | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different numeric severity value (e.g. firewall, IDS), your source's numeric severity should go to `event.severity`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `event.severity`. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.application | When a specific application or service is identified from network connection details (source/dest IPs, ports, certificates, or wire format), this field captures the application's or service's name. For example, the original event identifies the network connection being from a specific web service in a `https` network connection, like `facebook` or `twitter`. The field value must be normalized to lowercase for querying. | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.iana_number | IANA Protocol Number (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Standardized list of protocols. This aligns well with NetFlow and sFlow related logs which use the IANA Protocol Number. | keyword |
| network.inner | Network.inner fields are added in addition to network.vlan fields to describe the innermost VLAN when q-in-q VLAN tagging is present. Allowed fields include vlan.id and vlan.name. Inner vlan fields are typically used when sending traffic with multiple 802.1q encapsulations to a network sensor (e.g. Zeek, Wireshark.) | group |
| network.inner.vlan.id | VLAN ID as reported by the observer. | keyword |
| network.inner.vlan.name | Optional VLAN name as reported by the observer. | keyword |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| observer.egress.interface.name | Interface name as reported by the system. | keyword |
| observer.egress.zone | Network zone of outbound traffic as reported by the observer to categorize the destination area of egress traffic, e.g. Internal, External, DMZ, HR, Legal, etc. | keyword |
| observer.geo.city_name | City name. | keyword |
| observer.geo.continent_code | Two-letter code representing continent's name. | keyword |
| observer.geo.continent_name | Name of the continent. | keyword |
| observer.geo.country_iso_code | Country ISO code. | keyword |
| observer.geo.country_name | Country name. | keyword |
| observer.geo.location | Longitude and latitude. | geo_point |
| observer.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| observer.geo.postal_code | Postal code associated with the location. Values appropriate for this field may also be known as a postcode or ZIP code and will vary widely from country to country. | keyword |
| observer.geo.region_iso_code | Region ISO code. | keyword |
| observer.geo.region_name | Region name. | keyword |
| observer.geo.timezone | The time zone of the location, such as IANA time zone name. | keyword |
| observer.hostname | Hostname of the observer. | keyword |
| observer.ingress.interface.name | Interface name as reported by the system. | keyword |
| observer.ingress.zone | Network zone of incoming traffic as reported by the observer to categorize the source area of ingress traffic. e.g. internal, External, DMZ, HR, Legal, etc. | keyword |
| observer.ip | IP addresses of the observer. | ip |
| observer.name | Custom name of the observer. This is a name that can be given to an observer. This can be helpful for example if multiple firewalls of the same model are used in an organization. If no custom name is needed, the field can be left empty. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| observer.version | Observer version. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.pid | Process id. | long |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| rule.ruleset | Name of the ruleset, policy, group, or parent category in which the rule used to generate this event is a member. | keyword |
| rule.version | The version / revision of the rule being used for analysis. | keyword |
| server.address | Some event server addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| server.domain | The domain name of the server system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| server.user.name | Short name or login of the user. | keyword |
| server.user.name.text | Multi-field of `server.user.name`. | match_only_text |
| service.id | Unique identifier of the running service. If the service is comprised of many nodes, the `service.id` should be the same for all nodes. This id should uniquely identify the service. This makes it possible to correlate logs and metrics for one specific service, no matter which particular node emitted the event. Note that if you need to see the events from one specific host of the service, you should filter on that `host.name` or `host.id` instead. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_code | Two-letter code representing continent's name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| source.geo.postal_code | Postal code associated with the location. Values appropriate for this field may also be known as a postcode or ZIP code and will vary widely from country to country. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.geo.timezone | The time zone of the location, such as IANA time zone name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.nat.ip | Translated ip of source based NAT sessions (e.g. internal client to internet) Typically connections traversing load balancers, firewalls, or routers. | ip |
| source.nat.port | Translated port of source based NAT sessions. (e.g. internal client to internet) Typically used with load balancers, firewalls, or routers. | long |
| source.packets | Packets sent from the source to the destination. | long |
| source.port | Port of the source. | long |
| source.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| source.user.email | User email address. | keyword |
| source.user.group.name | Name of the group. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.full.text | Multi-field of `url.full`. | match_only_text |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.password | Password of the request. | keyword |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.registered_domain | The highest registered url domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| url.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| url.username | Username of the request. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |

