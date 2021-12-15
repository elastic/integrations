# Symantec Endpoint Protection Integration

This integration is for Symantec Endpoint Protection (SEP) logs. It can be used
to receive logs sent by SEP over syslog or read logs exported to a text file.

The log message is expected to be in CSV format. Syslog RFC3164 and RCF5424
headers are allowed and will be parsed if present. The data is mapped to
ECS fields where applicable and the remaining fields are written under
`symantec_endpoint.log.*`.

If a specific SEP log type is detected then `event.provider` is set (e.g.
`Agent Traffic Log`).

## Syslog setup steps

1. Enable this integration with the UDP input.
2. If the Symantec management server and Elastic Agent are running on different 
hosts then configure the integration to listen on 0.0.0.0 so that it will accept
UDP packets on all interfaces. This makes the listening port reachable by the
Symantec server.
3. Configure the Symantec management server to send syslog to the Elastic Agent
that is running this integration. See [_Exporting data to a Syslog server_](
https://techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-protection/all/Monitoring-Reporting-and-Enforcing-Compliance/viewing-logs-v7522439-d37e464/exporting-data-to-a-syslog-server-v8442743-d15e1107.html)
in the SEP guide. Use the IP address or hostname of the Elastic Agent as the
syslog server address. And use the listen port as the destination port (default
is 9008).

## Log file setup steps

1. Configure the Symantec management server to export log data to a text file.
See [Exporting log data to a text file](https://techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-protection/all/Monitoring-Reporting-and-Enforcing-Compliance/viewing-logs-v7522439-d37e464/exporting-log-data-to-a-text-file-v8440135-d15e1197.html).
2. Enable this integration with the log file input. Configure the input to
read from the location where the log files are being written. The default is
`C:\Program Files (x86)\Symantec\Symantec Endpoint Protection Manager\data\dump\*.log`.

Logs exported to text file always begin with the event time and severity
columns (e.g. `2020-01-16 08:00:31,Critical,...`).

## Log samples

Below are samples of some different SEP log types. These examples have had their
syslog header removed, but when sent over syslog these lines typically
begin with an RFC3164 header like
`<51>Oct 3 10:38:14 symantec.endpointprotection.test SymantecServer: `

### Administrative Log

Vendor documentation: https://knowledge.broadcom.com/external/article?legacyId=tech171741#Administrative

`Site: SEPSite,Server: SEPServer,Domain: _domainOrigin,Admin: _originUser,Administrator log on succeeded`

### Agent Activity Log

Vendor documentation: https://knowledge.broadcom.com/external/article?legacyId=tech171741#Agent_Activity

`Site: SEPSite,Server Name: exampleserver,Domain Name: Default,The management server received the client log successfully,TESTHOST01,sampleuser01,sample.example.com`

### Agent Behavior Log

Vendor documentation: https://knowledge.broadcom.com/external/article?legacyId=tech171741#Agent_Behavior

`exampleserver,216.160.83.57,Blocked,[AC7-2.1] Block scripts - Caller MD5=d73b04b0e696b0945283defa3eee4538,File Write,Begin: 2019-09-06 15:18:56,End: 2019-09-06 15:18:56,Rule: Rule Name,9552,C:/ProgramData/bomgar-scc-0x5d4162a4/bomgar-scc.exe,0,No Module Name,C:/ProgramData/bomgar-scc-0x5d4162a4/start-cb-hook.bat,User: _originUser,Domain: _domainOrigin,Action Type: ,File size (bytes): 1403,Device ID: SCSI\Disk&Ven_WDC&Prod_WD10SPCX-75KHST0\4&1d8ead7a&0&000200`

### Agent Packet Log

Vendor documentation: https://knowledge.broadcom.com/external/article?legacyId=tech171741#Agent_Packet

`exampleserver,Local Host: 81.2.69.143,Local Port: 138,Remote Host IP: 81.2.69.144.,Remote Host Name: ,Remote Port: 138,Outbound,Application: C:/windows/system32/NTOSKRNL.EXE,Action: Blocked`

### Agent Proactive Detection Log

Vendor documentation: https://knowledge.broadcom.com/external/article?legacyId=TECH171741#Agent_Proactive_Detection

`Potential risk found,Computer name: exampleComputer,Detection type: Heuristic,First Seen: Symantec has known about this file approximately 2 days.,Application name: Propsim,Application type: 127,"Application version: ""3",0,6,"0""",Hash type: SHA-256,Application hash: SHA#1234567890,Company name: Dummy Technologies,File size (bytes): 343040,Sensitivity: 2,Detection score: 3,COH Engine Version: 8.1.1.1,Detection Submissions No,Permitted application reason: MDS,Disposition: Bad,Download site: ,Web domain: ,Downloaded by: c:/programdata/oracle/java/javapath_target_2151967445/Host126,Prevalence: Unknown,Confidence: There is not enough information about this file to recommend it.,URL Tracking Status: Off,Risk Level: High,Detection Source: N/A,Source: Heuristic Scan,Risk name: ,Occurrences: 1,f:\user\workspace\baseline package creator\release\Host214,'',Actual action: Left alone,Requested action: Left alone,Secondary action: Left alone,Event time: 2018-02-16 08:01:33,Inserted: 2018-02-16 08:02:52,End: 2018-02-16 08:01:33,Domain: Default,Group: My Company\SEPM Group Name,Server: SEPMServer,User: exampleUser,Source computer: ,Source IP:`

### Agent Risk Log

Vendor documentation: https://knowledge.broadcom.com/external/article?legacyId=TECH171741#Agent_Risk

`Security risk found,IP Address: 1.128.3.4,Computer name: exampleComputer,Source: Auto-Protect scan,Risk name: WS.Reputation.1,Occurrences: 1,e:\removablemediaaccessutility.exe,,Actual action: All actions failed,Requested action: Process terminate pending restart,Secondary action: Left alone,Event time: 2019-09-03 08:12:25,Inserted: 2019-09-03 08:14:03,End: 2019-09-03 08:12:25,Last update time: 2019-09-03 08:14:03,Domain: SEPMServerDoman,Group: My Company\GroupName,Server: SEPMServerName,User: exampleUser,Source computer: ,Source IP: ,Disposition: Bad,Download site: ,Web domain: ,Downloaded by: e:/removablemediaaccessutility.exe,Prevalence: This file has been seen by fewer than 5 Symantec users.,Confidence: There is some evidence that this file is untrustworthy.,URL Tracking Status: On,First Seen: Symantec has known about this file approximately 2 days.,Sensitivity: ,Permitted application reason: Not on the permitted application list,Application hash: SHA#1234567890,Hash type: SHA2,Company name: Company Name,Application name: Client for Symantec Endpoint Encryption,Application version: 11.1.2 (Build 1248),Application type: 127,File size (bytes): 4193981,Category set: Malware,Category type: Insight Network Threat,Location: GD-OTS Unmanaged Client - Online,Intensive Protection Level: 0,Certificate issuer: Symantec Corporation,Certificate signer: VeriSign Class 3 Code Signing 2010 CA,Certificate thumbprint: AB6EF1497C6E1C8CCC12F06E945A4954FB41AD45,Signing timestamp: 1482491555,Certificate serial number: AB2D17E62E571F288ACB5666FD3C5230`

### Agent Scan Log

Vendor documentation: https://knowledge.broadcom.com/external/article?legacyId=TECH171741#Agent_Scan

`Scan ID: 123456789,Begin: 2020-01-31 11:35:28,End: 2020-01-31 11:45:28,Started,Duration (seconds): 600,User1: exampleUser,User2: SYSTEM,Scan started on selected drives and folders and all extensions.,Scan Complete:  Risks: 0   Scanned: 916   Files/Folders/Drives Omitted: 0 Trusted Files Skipped: 0,Command: Not a command scan (),Threats: 0,Infected: 0,Total files: 916,Omitted: 0,Computer: _destinationHostname,IP Address: 1.128.3.4,Domain: exampleDomain,Group: Company\US\UserWS\Main Office,Server: SEPServer`

### Agent Security Log

Vendor documentation: https://knowledge.broadcom.com/external/article?legacyId=TECH171741#Agent_Security

`server03,Event Description: ARP Cache Poison,Local Host IP: 0.0.0.0,Local Host MAC: 2DFF88AABBDC,Remote Host Name: ,Remote Host IP: 0.0.0.0,Remote Host MAC: AABBCCDDEEFF,Inbound,Unknown,Intrusion ID: 0,Begin: 2020-11-23 13:56:35,End Time: 2020-11-23 13:56:35,Occurrences: 1,Application: ,Location: Remote,User Name: bobby,Domain Name: local,Local Port: 0,Remote Port: 0,CIDS Signature ID: 99990,CIDS Signature string: ARP Cache Poison,CIDS Signature SubID: 0,Intrusion URL: ,Intrusion Payload URL: ,SHA-256: ,MD-5:`

### Agent System Log

Vendor documentation: https://knowledge.broadcom.com/external/article?legacyId=TECH171741#Agent_System

`exampleHostname,Category: 0,CVE,New content update failed to download from the management server.     Remote file path: https://server:443/content/{02335EF8-ADE1-4DD8-9F0F-2A9662352E65}/190815061/xdelta190815061_To_190816061.dax,Event time: 2019-08-19 07:14:38`

### Agent Traffic Log

Vendor documentation: https://knowledge.broadcom.com/external/article?legacyId=TECH171741#Agent_Traffic

`host-plaintext,Local Host IP: 216.160.83.61,Local Port: 80,Local Host MAC: CCF9E4A91226,Remote Host IP: 216.160.83.61,Remote Host Name: ,Remote Port: 33424,Remote Host MAC: 2C3AFDA79E71,TCP,Inbound,Begin: 2020-11-11 19:25:21,End Time: 2020-11-11 19:25:28,Occurrences: 4,Application: C:/WINDOWS/system32/NTOSKRNL.EXE,Rule: Block Unapproved Incoming Ports,Location: Default,User Name: sampleuser4,Domain Name: SMPL,Action: Blocked,SHA-256: 5379732000000000000000000000000000000000000000000000000000000000,MD-5: 53797320000000000000000000000000`

### Policy Log

Vendor documentation: https://knowledge.broadcom.com/external/article?legacyId=TECH171741#Policy

`Site: SEPSite,Server: exampleHostname,Domain: exampleDomain,Admin: exampleAdmin,Event Description: Policy has been edited: Edited shared Intrusion Prevention policy: SEPPolicyName,SEPPolicyName`

### System Log

Vendor documentation: https://knowledge.broadcom.com/external/article?legacyId=TECH171741#System

`Site: SEPSite,Server: exampleHostname,Symantec Endpoint Protection Manager could not update Intrusion Prevention Signatures 14.0.`

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
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
| destination.domain | Destination domain. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.mac | MAC address of the destination. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| destination.packets | Packets sent from the destination to the source. | long |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.pe.company | Internal company name of the file, provided at compile-time. | keyword |
| file.pe.file_version | Internal version of the file, provided at compile-time. | keyword |
| file.pe.product | Internal product name of the file, provided at compile-time. | keyword |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| file.x509.issuer.common_name | List of common name (CN) of issuing certificate authority. | keyword |
| file.x509.not_before | Time at which the certificate is first considered valid. | date |
| file.x509.serial_number | Unique serial number issued by the certificate authority. For consistency, if this value is alphanumeric, it should be formatted without colons and uppercase characters. | keyword |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| log.syslog.host.hostname |  | keyword |
| log.syslog.priority |  | long |
| log.syslog.process.name |  | keyword |
| log.syslog.process.pid |  | long |
| log.syslog.structured_data |  | flattened |
| log.syslog.version |  | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| observer.product | The product name of the observer. | constant_keyword |
| observer.type | The type of the observer the data is coming from. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.hash.md5 | MD5 hash. | keyword |
| process.hash.sha256 | SHA256 hash. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.pid | Process id. | long |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.domain | Source domain. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| source.port | Port of the source. | long |
| symantec_endpoint.log._uid |  | keyword |
| symantec_endpoint.log.action |  | keyword |
| symantec_endpoint.log.actual_action |  | keyword |
| symantec_endpoint.log.admin |  | keyword |
| symantec_endpoint.log.api_name |  | keyword |
| symantec_endpoint.log.application |  | keyword |
| symantec_endpoint.log.application_hash |  | keyword |
| symantec_endpoint.log.application_name |  | keyword |
| symantec_endpoint.log.application_type |  | keyword |
| symantec_endpoint.log.application_version |  | keyword |
| symantec_endpoint.log.begin |  | keyword |
| symantec_endpoint.log.caller_process_id |  | keyword |
| symantec_endpoint.log.caller_process_name |  | keyword |
| symantec_endpoint.log.caller_return_address |  | keyword |
| symantec_endpoint.log.caller_return_module_name |  | keyword |
| symantec_endpoint.log.category |  |  |
| symantec_endpoint.log.category_set |  | keyword |
| symantec_endpoint.log.category_type |  | keyword |
| symantec_endpoint.log.certificate_issuer |  | keyword |
| symantec_endpoint.log.certificate_serial_number |  | keyword |
| symantec_endpoint.log.certificate_signer |  | keyword |
| symantec_endpoint.log.certificate_thumbprint |  | keyword |
| symantec_endpoint.log.cids_signature_id |  | keyword |
| symantec_endpoint.log.cids_signature_string |  | keyword |
| symantec_endpoint.log.cids_signature_subid |  | keyword |
| symantec_endpoint.log.coh_engine_version |  | keyword |
| symantec_endpoint.log.command |  | keyword |
| symantec_endpoint.log.company_name |  | keyword |
| symantec_endpoint.log.computer |  | keyword |
| symantec_endpoint.log.computer_name |  | keyword |
| symantec_endpoint.log.confidence |  | keyword |
| symantec_endpoint.log.description | Description of the virus file. | keyword |
| symantec_endpoint.log.detection_score |  | keyword |
| symantec_endpoint.log.detection_source |  | keyword |
| symantec_endpoint.log.detection_type |  | keyword |
| symantec_endpoint.log.device_id |  | keyword |
| symantec_endpoint.log.disposition |  | keyword |
| symantec_endpoint.log.domain_name |  | keyword |
| symantec_endpoint.log.download_site | The URL determined from where the image was downloaded. | keyword |
| symantec_endpoint.log.downloaded_by |  | keyword |
| symantec_endpoint.log.duration_(seconds) |  | keyword |
| symantec_endpoint.log.end |  | keyword |
| symantec_endpoint.log.event_description |  | keyword |
| symantec_endpoint.log.event_source |  | keyword |
| symantec_endpoint.log.event_time |  | date |
| symantec_endpoint.log.file_path |  | keyword |
| symantec_endpoint.log.file_size_bytes |  | keyword |
| symantec_endpoint.log.first_seen |  | keyword |
| symantec_endpoint.log.group |  | keyword |
| symantec_endpoint.log.hash_type |  | keyword |
| symantec_endpoint.log.infected |  | keyword |
| symantec_endpoint.log.inserted |  | date |
| symantec_endpoint.log.intensive_protection_level |  | keyword |
| symantec_endpoint.log.intrusion_id |  | keyword |
| symantec_endpoint.log.intrusion_payload_url |  | keyword |
| symantec_endpoint.log.intrusion_url |  | keyword |
| symantec_endpoint.log.ip_address |  | keyword |
| symantec_endpoint.log.last_update_time |  | date |
| symantec_endpoint.log.local_host |  | keyword |
| symantec_endpoint.log.local_host_ip |  | keyword |
| symantec_endpoint.log.local_host_mac |  | keyword |
| symantec_endpoint.log.local_host_name |  | keyword |
| symantec_endpoint.log.local_port |  | keyword |
| symantec_endpoint.log.location |  | keyword |
| symantec_endpoint.log.md-5 |  | keyword |
| symantec_endpoint.log.network_protocol |  | keyword |
| symantec_endpoint.log.occurrences |  | keyword |
| symantec_endpoint.log.omitted |  | keyword |
| symantec_endpoint.log.parameters |  | keyword |
| symantec_endpoint.log.permitted_application_reason |  | keyword |
| symantec_endpoint.log.policy_name |  | keyword |
| symantec_endpoint.log.prevalence |  | keyword |
| symantec_endpoint.log.remote_host_ip |  | keyword |
| symantec_endpoint.log.remote_host_mac |  | keyword |
| symantec_endpoint.log.remote_port |  | keyword |
| symantec_endpoint.log.requested_action |  | keyword |
| symantec_endpoint.log.risk_level |  | keyword |
| symantec_endpoint.log.risk_name |  | keyword |
| symantec_endpoint.log.risk_type | Localized strings for Heuristic / Cookie / Admin Black List / BPE / System Change / N/A. | keyword |
| symantec_endpoint.log.rule |  | keyword |
| symantec_endpoint.log.scan_complete |  | keyword |
| symantec_endpoint.log.scan_id |  | keyword |
| symantec_endpoint.log.secondary_action |  | keyword |
| symantec_endpoint.log.sensitivity |  | keyword |
| symantec_endpoint.log.server |  | keyword |
| symantec_endpoint.log.server_name |  | keyword |
| symantec_endpoint.log.sha-256 |  | keyword |
| symantec_endpoint.log.signing_timestamp |  | date |
| symantec_endpoint.log.site |  | keyword |
| symantec_endpoint.log.source |  | keyword |
| symantec_endpoint.log.source_computer |  | keyword |
| symantec_endpoint.log.source_ip |  | keyword |
| symantec_endpoint.log.submission_recommended | Recommendation on whether to submit this detection to Symantec. | boolean |
| symantec_endpoint.log.threats |  | keyword |
| symantec_endpoint.log.total_file |  | keyword |
| symantec_endpoint.log.total_files |  | keyword |
| symantec_endpoint.log.traffic_direction |  | keyword |
| symantec_endpoint.log.url_tracking_status |  | keyword |
| symantec_endpoint.log.user1 | User when scan started. | keyword |
| symantec_endpoint.log.user2 | User when scan ended. | keyword |
| symantec_endpoint.log.user_name |  | keyword |
| symantec_endpoint.log.web_domain | The web domain. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.path | Path of the request, such as "/search". | wildcard |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.name | Short name or login of the user. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |


An example event for `log` looks as following:

```json
{
    "agent": {
        "hostname": "docker-fleet-agent",
        "name": "docker-fleet-agent",
        "id": "b939be80-6333-41b5-8e7a-f31a283b225c",
        "ephemeral_id": "d7a48626-5b82-4be5-ba4f-ad6fb87f8d83",
        "type": "filebeat",
        "version": "7.16.0"
    },
    "process": {
        "executable": "C:/WINDOWS/system32/NTOSKRNL.EXE",
        "hash": {
            "sha256": "5379732000000000000000000000000000000000000000000000000000000000",
            "md5": "53797320000000000000000000000000"
        }
    },
    "log": {
        "source": {
            "address": "192.168.160.4:42303"
        },
        "syslog": {
            "process": {
                "name": "myproc",
                "pid": 8710
            },
            "host": {
                "hostname": "192.0.2.1"
            },
            "priority": 165,
            "version": 1
        }
    },
    "elastic_agent": {
        "id": "b939be80-6333-41b5-8e7a-f31a283b225c",
        "version": "7.16.0",
        "snapshot": true
    },
    "destination": {
        "geo": {
            "name": "Default"
        },
        "port": 80,
        "ip": "192.168.1.113",
        "mac": "CC-F9-E4-A9-12-26"
    },
    "rule": {
        "name": "Block Unapproved Incoming Ports"
    },
    "source": {
        "port": 33424,
        "ip": "192.168.1.1",
        "mac": "2C-3A-FD-A7-9E-71"
    },
    "network": {
        "community_id": "1:TbyoH4bYJO0/cP/YShIpq9J+Z3s=",
        "transport": "tcp",
        "direction": "ingress"
    },
    "tags": [
        "preserve_original_event",
        "symantec-endpoint-log",
        "forwarded"
    ],
    "observer": {
        "product": "Endpoint Protection",
        "vendor": "Symantec",
        "type": "edr"
    },
    "input": {
        "type": "udp"
    },
    "@timestamp": "2021-11-16T12:14:15.000Z",
    "ecs": {
        "version": "1.12.0"
    },
    "related": {
        "ip": [
            "192.168.1.113",
            "192.168.1.1"
        ],
        "hash": [
            "53797320000000000000000000000000",
            "5379732000000000000000000000000000000000000000000000000000000000"
        ]
    },
    "data_stream": {
        "namespace": "ep",
        "type": "logs",
        "dataset": "symantec_endpoint.log"
    },
    "host": {
        "hostname": "host-rfc5424",
        "ip": [
            "192.168.1.113"
        ],
        "mac": [
            "CC-F9-E4-A9-12-26"
        ]
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2021-11-25T00:36:04Z",
        "original": "\u003c165\u003e1 2021-11-16T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - host-rfc5424,Local Host IP: 192.168.1.113,Local Port: 80,Local Host MAC: CCF9E4A91226,Remote Host IP: 192.168.1.1,Remote Host Name: ,Remote Port: 33424,Remote Host MAC: 2C3AFDA79E71,TCP,Inbound,Begin: 2020-11-11 19:25:21,End Time: 2020-11-11 19:25:28,Occurrences: 4,Application: C:/WINDOWS/system32/NTOSKRNL.EXE,Rule: Block Unapproved Incoming Ports,Location: Default,User Name: sampleuser4,Domain Name: SMPL,Action: Blocked,SHA-256: 5379732000000000000000000000000000000000000000000000000000000000,MD-5: 53797320000000000000000000000000",
        "provider": "Agent Traffic Log",
        "kind": "event",
        "start": "2020-11-11T19:25:21.000Z",
        "count": 4,
        "action": "blocked",
        "end": "2020-11-11T19:25:28.000Z",
        "category": [
            "intrusion_detection",
            "network"
        ],
        "type": [
            "connection",
            "process",
            "denied"
        ],
        "dataset": "symantec_endpoint.log"
    },
    "user": {
        "domain": "SMPL",
        "name": "sampleuser4"
    }
}
```
