# Cisco Secure Endpoint Integration

This integration is for [Cisco Secure Endpoint](https://developer.cisco.com/amp-for-endpoints/) logs. It includes the following datasets for receiving logs over syslog or read from a file:

- `event` dataset: supports Cisco Secure Endpoint Event logs.

## Logs

### Secure Endpoint

The `event` dataset collects Cisco Secure Endpoint logs.

An example event for `event` looks as following:

```json
{
    "@timestamp": "2021-01-13T10:13:08.000Z",
    "agent": {
        "ephemeral_id": "1bee52ec-b713-415e-9d9b-32c5217f9796",
        "id": "83d8d392-d20c-40ef-a257-bf9cf314d1db",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "cisco": {
        "secure_endpoint": {
            "cloud_ioc": {
                "description": "Microsoft Word launched PowerShell. This is indicative of multiple dropper variants that make use of Visual Basic Application macros to perform nefarious activities, such as downloading and executing malicious executables.",
                "short_description": "W32.WinWord.Powershell"
            },
            "computer": {
                "active": true,
                "connector_guid": "test_connector_guid",
                "external_ip": "8.8.8.8",
                "network_addresses": [
                    {
                        "ip": "10.10.10.10",
                        "mac": "38:1e:eb:ba:2c:15"
                    }
                ]
            },
            "connector_guid": "test_connector_guid",
            "event_type_id": 1107296274,
            "file": {
                "disposition": "Clean",
                "identity": {},
                "parent": {
                    "disposition": "Clean",
                    "identity": {}
                }
            },
            "group_guids": [
                "test_group_guid"
            ],
            "related": {
                "mac": [
                    "38-1E-EB-BA-2C-15"
                ]
            }
        }
    },
    "data_stream": {
        "dataset": "cisco_secure_endpoint.event",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "83d8d392-d20c-40ef-a257-bf9cf314d1db",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "action": "Cloud IOC",
        "agent_id_status": "verified",
        "category": [
            "file"
        ],
        "code": "1107296274",
        "created": "2022-04-13T11:54:03.909Z",
        "dataset": "cisco_secure_endpoint.event",
        "id": "1515298355162029000",
        "ingested": "2022-04-13T11:54:04Z",
        "kind": "alert",
        "original": "{\"data\":{\"cloud_ioc\":{\"description\":\"Microsoft Word launched PowerShell. This is indicative of multiple dropper variants that make use of Visual Basic Application macros to perform nefarious activities, such as downloading and executing malicious executables.\",\"short_description\":\"W32.WinWord.Powershell\"},\"computer\":{\"active\":true,\"connector_guid\":\"test_connector_guid\",\"external_ip\":\"8.8.8.8\",\"hostname\":\"Demo_AMP\",\"links\":{\"computer\":\"https://api.eu.amp.cisco.com/v1/computers/test_computer\",\"group\":\"https://api.eu.amp.cisco.com/v1/groups/test_group\",\"trajectory\":\"https://api.eu.amp.cisco.com/v1/computers/test_computer/trajectory\"},\"network_addresses\":[{\"ip\":\"10.10.10.10\",\"mac\":\"38:1e:eb:ba:2c:15\"}]},\"connector_guid\":\"test_connector_guid\",\"date\":\"2021-01-13T10:13:08+00:00\",\"event_type\":\"Cloud IOC\",\"event_type_id\":1107296274,\"file\":{\"disposition\":\"Clean\",\"file_name\":\"PowerShell.exe\",\"file_path\":\"/C:/Windows/SysWOW64/WindowsPowerShell/v1.0/PowerShell.exe\",\"identity\":{\"sha256\":\"6c05e11399b7e3c8ed31bae72014cf249c144a8f4a2c54a758eb2e6fad47aec7\"},\"parent\":{\"disposition\":\"Clean\",\"identity\":{\"sha256\":\"3d46e95284f93bbb76b3b7e1bf0e1b2d51e8a9411c2b6e649112f22f92de63c2\"}}},\"group_guids\":[\"test_group_guid\"],\"id\":1515298355162029000,\"severity\":\"Medium\",\"start_date\":\"2021-01-13T10:13:08+00:00\",\"start_timestamp\":1610532788,\"timestamp\":1610532788,\"timestamp_nanoseconds\":162019000},\"metadata\":{\"links\":{\"next\":\"http://7d3a7ffa9a19:8080/v1/events?start_date=2022-04-12T11:54:03+00:00\\u0026limit=1\\u0026offset=1\",\"self\":\"http://7d3a7ffa9a19:8080/v1/events?start_date=2022-04-12T11:54:03+00:00\\u0026limit=1\"},\"results\":{\"current_item_count\":1,\"index\":0,\"items_per_page\":1,\"total\":2}},\"version\":\"v1.2.0\"}",
        "severity": 2,
        "start": "2021-01-13T10:13:08.000Z"
    },
    "file": {
        "hash": {
            "sha256": "6c05e11399b7e3c8ed31bae72014cf249c144a8f4a2c54a758eb2e6fad47aec7"
        },
        "name": "PowerShell.exe",
        "path": "/C:/Windows/SysWOW64/WindowsPowerShell/v1.0/PowerShell.exe"
    },
    "host": {
        "hostname": "Demo_AMP",
        "name": "Demo_AMP"
    },
    "input": {
        "type": "httpjson"
    },
    "process": {
        "hash": {
            "sha256": "3d46e95284f93bbb76b3b7e1bf0e1b2d51e8a9411c2b6e649112f22f92de63c2"
        }
    },
    "related": {
        "hash": [
            "6c05e11399b7e3c8ed31bae72014cf249c144a8f4a2c54a758eb2e6fad47aec7"
        ],
        "hosts": [
            "Demo_AMP"
        ],
        "ip": [
            "8.8.8.8",
            "10.10.10.10"
        ]
    },
    "tags": [
        "cisco-secure_endpoint",
        "forwarded",
        "preserve_original_event"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cisco.secure_endpoint.bp_data | Endpoint isolation information | flattened |
| cisco.secure_endpoint.cloud_ioc.description | Description of the related IOC for specific IOC events from AMP. | keyword |
| cisco.secure_endpoint.cloud_ioc.short_description | Short description of the related IOC for specific IOC events from AMP. | keyword |
| cisco.secure_endpoint.command_line.arguments | The CLI arguments related to the Cloud Threat IOC reported by Cisco. | keyword |
| cisco.secure_endpoint.computer.active | If the current endpoint is active or not. | boolean |
| cisco.secure_endpoint.computer.connector_guid | The GUID of the connector, similar to top level connector_guid, but unique if multiple connectors are involved. | keyword |
| cisco.secure_endpoint.computer.external_ip | The external IP of the related host. | ip |
| cisco.secure_endpoint.computer.network_addresses | All network interface information on the related host. | flattened |
| cisco.secure_endpoint.connector_guid | The GUID of the connector sending information to AMP. | keyword |
| cisco.secure_endpoint.detection | The name of the malware detected. | keyword |
| cisco.secure_endpoint.detection_id | The ID of the detection. | keyword |
| cisco.secure_endpoint.error.description | Description of an endpoint error event. | keyword |
| cisco.secure_endpoint.error.error_code | The error code describing the related error event. | long |
| cisco.secure_endpoint.event_type_id | A sub ID of the event, depending on event type. | long |
| cisco.secure_endpoint.file.archived_file.disposition | Categorization of a file archive related to a file, for example "Malicious" or "Clean". | keyword |
| cisco.secure_endpoint.file.archived_file.identity.md5 | MD5 hash of the archived file related to the malicious event. | keyword |
| cisco.secure_endpoint.file.archived_file.identity.sha1 | SHA1 hash of the archived file related to the malicious event. | keyword |
| cisco.secure_endpoint.file.archived_file.identity.sha256 | SHA256 hash of the archived file related to the malicious event. | keyword |
| cisco.secure_endpoint.file.attack_details.application | The application name related to Exploit Prevention events. | keyword |
| cisco.secure_endpoint.file.attack_details.attacked_module | Path to the executable or dll that was attacked and detected by Exploit Prevention. | keyword |
| cisco.secure_endpoint.file.attack_details.base_address | The base memory address related to the exploit detected. | keyword |
| cisco.secure_endpoint.file.attack_details.indicators | Different indicator types that matches the exploit detected, for example different MITRE tactics. | flattened |
| cisco.secure_endpoint.file.attack_details.suspicious_files | An array of related files when an attack is detected by Exploit Prevention. | keyword |
| cisco.secure_endpoint.file.disposition | Categorization of file, for example "Malicious" or "Clean". | keyword |
| cisco.secure_endpoint.file.parent.disposition | Categorization of parrent, for example "Malicious" or "Clean". | keyword |
| cisco.secure_endpoint.group_guids | An array of group GUIDS related to the connector sending information to AMP. | keyword |
| cisco.secure_endpoint.network_info.disposition | Categorization of a network event related to a file, for example "Malicious" or "Clean". | keyword |
| cisco.secure_endpoint.network_info.nfm.direction | The current direction based on source and destination IP. | keyword |
| cisco.secure_endpoint.network_info.parent.disposition | Categorization of a IOC for example "Malicious" or "Clean". | keyword |
| cisco.secure_endpoint.network_info.parent.identify.sha256 | SHA256 hash of the related IOC. | keyword |
| cisco.secure_endpoint.network_info.parent.identity.md5 | MD5 hash of the related IOC. | keyword |
| cisco.secure_endpoint.network_info.parent.identity.sha1 | SHA1 hash of the related IOC. | keyword |
| cisco.secure_endpoint.related.cve | An array of all related CVEs | keyword |
| cisco.secure_endpoint.related.mac | An array of all related MAC addresses. | keyword |
| cisco.secure_endpoint.scan.clean | Boolean value if a scanned file was clean or not. | boolean |
| cisco.secure_endpoint.scan.description | Description of an event related to a scan being initiated, for example the specific directory name. | keyword |
| cisco.secure_endpoint.scan.malicious_detections | Count of malicious files or documents detected related to a single scan event. | long |
| cisco.secure_endpoint.scan.scanned_files | Count of files scanned in a directory. | long |
| cisco.secure_endpoint.scan.scanned_paths | Count of different directories scanned related to a single scan event. | long |
| cisco.secure_endpoint.scan.scanned_processes | Count of processes scanned related to a single scan event. | long |
| cisco.secure_endpoint.tactics | List of all MITRE tactics related to the incident found. | flattened |
| cisco.secure_endpoint.techniques | List of all MITRE techniques related to the incident found. | flattened |
| cisco.secure_endpoint.threat_hunting.incident_end_time | When the threat hunt finalized or closed. | date |
| cisco.secure_endpoint.threat_hunting.incident_hunt_guid | The GUID of the related investigation tracking issue. | keyword |
| cisco.secure_endpoint.threat_hunting.incident_id | The id of the related incident for the threat hunting activity. | long |
| cisco.secure_endpoint.threat_hunting.incident_remediation | Recommendations to resolve the vulnerability or exploited host. | keyword |
| cisco.secure_endpoint.threat_hunting.incident_report_guid | The GUID of the related threat hunting report. | keyword |
| cisco.secure_endpoint.threat_hunting.incident_start_time | When the threat hunt was initiated. | date |
| cisco.secure_endpoint.threat_hunting.incident_summary | Summary of the outcome on the threat hunting activity. | keyword |
| cisco.secure_endpoint.threat_hunting.incident_title | Title of the incident related to the threat hunting activity. | keyword |
| cisco.secure_endpoint.threat_hunting.severity | Severity result of the threat hunt registered to the malicious event. Can be Low-Critical. | keyword |
| cisco.secure_endpoint.threat_hunting.tactics | List of all MITRE tactics related to the incident found. | flattened |
| cisco.secure_endpoint.threat_hunting.techniques | List of all MITRE techniques related to the incident found. | flattened |
| cisco.secure_endpoint.timestamp_nanoseconds | The timestamp in Epoch nanoseconds. | date |
| cisco.secure_endpoint.vulnerabilities | An array of related vulnerabilities to the malicious event. | flattened |
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
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
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
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.hash.md5 | MD5 hash. | keyword |
| process.hash.sha1 | SHA1 hash. | keyword |
| process.hash.sha256 | SHA256 hash. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.pid | Process id. | long |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| threat.tactic.id | The id of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/ ) | keyword |
| threat.tactic.name | Name of the type of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/) | keyword |
| threat.tactic.reference | The reference url of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/ ) | keyword |
| threat.technique.id | The id of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| threat.technique.name | The name of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| threat.technique.name.text | Multi-field of `threat.technique.name`. | match_only_text |
| threat.technique.reference | The reference url of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |

