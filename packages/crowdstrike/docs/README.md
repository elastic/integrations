# CrowdStrike Integration

This integration is for [CrowdStrike](https://www.crowdstrike.com/resources/?cs_query=type=5) products. It includes the
following datasets for receiving logs:

- `falcon` dataset: consists of endpoint data and Falcon platform audit data forwarded from [Falcon SIEM Connector](https://www.crowdstrike.com/blog/tech-center/integrate-with-your-siem/).
- `fdr` dataset: consists of logs forwarded using the [Falcon Data Replicator](https://github.com/CrowdStrike/FDR).

## Compatibility

This integration supports CrowdStrike Falcon SIEM-Connector-v2.0.

## Logs

### Falcon

Contains endpoint data and CrowdStrike Falcon platform audit data forwarded from Falcon SIEM Connector.

#### Falcon SIEM Connector configuration file

By default, the configuration file located at `/opt/crowdstrike/etc/cs.falconhoseclient.cf` provides configuration options related to the events collected by Falcon SIEM Connector.

Parts of the configuration file called `EventTypeCollection` and `EventSubTypeCollection` provides a list of event types that the connector should collect.

Current supported event types are:
- DetectionSummaryEvent
- IncidentSummaryEvent
- UserActivityAuditEvent
- AuthActivityAuditEvent
- FirewallMatchEvent
- RemoteResponseSessionStartEvent
- RemoteResponseSessionEndEvent
- CSPM Streaming events
- CSPM Search events
- IDP Incidents
- IDP Summary events
- Mobile Detection events
- Recon Notification events
- XDR Detection events

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |
| agent.name | Custom name of the agent. This is a name that can be given to an agent. This can be helpful if for example two Filebeat instances are running on the same host but a human readable separation is needed on which Filebeat instance data is coming from. | keyword |
| agent.type | Type of the agent. The agent type always stays the same and should be given by the agent used. In case of Filebeat the agent would always be Filebeat also if two Filebeat instances are run on the same machine. | keyword |
| agent.version | Version of the agent. | keyword |
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
| crowdstrike.event.AccountCreationTimeStamp | The timestamp of when the source account was created in Active Directory. | date |
| crowdstrike.event.ActivityId | ID of the activity that triggered the detection. | keyword |
| crowdstrike.event.AddedPrivilege | The difference between their current and previous list of privileges. | keyword |
| crowdstrike.event.AdditionalAccountObjectGuid | Additional involved user object GUID. | keyword |
| crowdstrike.event.AdditionalAccountObjectSid | Additional involved user object SID. | keyword |
| crowdstrike.event.AdditionalAccountUpn | Additional involved user UPN. | keyword |
| crowdstrike.event.AdditionalActivityId | ID of an additional activity related to the detection. | keyword |
| crowdstrike.event.AdditionalEndpointAccountObjectGuid | Additional involved endpoint object GUID. | keyword |
| crowdstrike.event.AdditionalEndpointAccountObjectSid | Additional involved endpoint object SID. | keyword |
| crowdstrike.event.AdditionalEndpointSensorId | Additional involved endpoint agent ID. | keyword |
| crowdstrike.event.AdditionalLocationCountryCode | Additional involved country code. | keyword |
| crowdstrike.event.AdditionalSsoApplicationIdentifier | Additional application identifier. | keyword |
| crowdstrike.event.AnomalousTicketContentClassification | Ticket signature analysis. | keyword |
| crowdstrike.event.AssociatedFile | The file associated with the triggering indicator. | keyword |
| crowdstrike.event.Attributes | JSON objects containing additional information about the event. | flattened |
| crowdstrike.event.AuditKeyValues | Fields that were changed in this event. | nested |
| crowdstrike.event.Category | IDP incident category. | keyword |
| crowdstrike.event.CertificateTemplateIdentifier | The ID of the certificate template. | keyword |
| crowdstrike.event.CertificateTemplateName | Name of the certificate template. | keyword |
| crowdstrike.event.Certificates | Provides one or more JSON objects which includes related SSL/TLS Certificates. | nested |
| crowdstrike.event.Commands | Commands run in a remote session. | keyword |
| crowdstrike.event.ComputerName | Name of the computer where the detection occurred. | keyword |
| crowdstrike.event.CustomerId | Customer identifier. | keyword |
| crowdstrike.event.DataDomains | Data domains of the event that was the primary indicator or created it. | keyword |
| crowdstrike.event.DetectId | Unique ID associated with the detection. | keyword |
| crowdstrike.event.DetectName | Name of the detection. | keyword |
| crowdstrike.event.DeviceId | Device on which the event occurred. | keyword |
| crowdstrike.event.DnsRequests | Detected DNS requests done by a process. | nested |
| crowdstrike.event.DocumentsAccessed | Detected documents accessed by a process. | nested |
| crowdstrike.event.EmailAddresses | Summary list of all associated entity email addresses. | keyword |
| crowdstrike.event.EnvironmentVariables | Provides one or more JSON objects which includes related environment variables. | nested |
| crowdstrike.event.EventType | CrowdStrike provided event type. | keyword |
| crowdstrike.event.ExecutablesWritten | Detected executables written to disk by a process. | nested |
| crowdstrike.event.Finding | The details of the finding. | keyword |
| crowdstrike.event.FineScore | The highest incident score reached as of the time the event was sent. | float |
| crowdstrike.event.Flags.Audit | CrowdStrike audit flag. | boolean |
| crowdstrike.event.Flags.Log | CrowdStrike log flag. | boolean |
| crowdstrike.event.Flags.Monitor | CrowdStrike monitor flag. | boolean |
| crowdstrike.event.GrandparentCommandLine | Grandparent process command line arguments. | keyword |
| crowdstrike.event.GrandparentImageFileName | Path to the grandparent process. | keyword |
| crowdstrike.event.Highlights | Sections of content that matched the monitoring rule. | text |
| crowdstrike.event.HostGroups | Array of related Host Group IDs. | keyword |
| crowdstrike.event.ICMPCode | RFC2780 ICMP Code field. | keyword |
| crowdstrike.event.ICMPType | RFC2780 ICMP Type field. | keyword |
| crowdstrike.event.IOARuleInstanceVersion | Version number of the InstanceID that triggered. | long |
| crowdstrike.event.IOARuleName | Name given to the custom IOA rule that triggered. | keyword |
| crowdstrike.event.IOCType | CrowdStrike type for indicator of compromise. | keyword |
| crowdstrike.event.IOCValue | CrowdStrike value for indicator of compromise. | keyword |
| crowdstrike.event.IdpPolicyRuleAction | Identity Protection policy rule action. | keyword |
| crowdstrike.event.IdpPolicyRuleName | Identity Protection policy rule name. | keyword |
| crowdstrike.event.IdpPolicyRuleTrigger | Identity Protection policy rule trigger. | keyword |
| crowdstrike.event.IncidentType | Incident Type | keyword |
| crowdstrike.event.Ipv | Protocol for network request. | keyword |
| crowdstrike.event.ItemPostedTimestamp | Time the raw intelligence was posted. | date |
| crowdstrike.event.ItemType | Type of raw intelligence. | keyword |
| crowdstrike.event.KeyStoreErrors | Describes a KeyStore error. | keyword |
| crowdstrike.event.LMHostIDs | Array of host IDs seen to have experienced lateral movement because of the incident. | keyword |
| crowdstrike.event.LateralMovement | Lateral movement field for incident. | long |
| crowdstrike.event.LdapSearchQueryAttack | Detected LDAP tool attack. | keyword |
| crowdstrike.event.LoadedObjects | Provides one or more JSON objects describing the loaded objects related to the detection. | nested |
| crowdstrike.event.LocalIP | IP address of the host associated with the detection. | keyword |
| crowdstrike.event.MACAddress | MAC address of the host associated with the detection. | keyword |
| crowdstrike.event.MD5String | MD5 sum of the executable associated with the detection. | keyword |
| crowdstrike.event.MachineDomain | Domain for the machine associated with the detection. | keyword |
| crowdstrike.event.MatchCount | Number of firewall rule matches. | long |
| crowdstrike.event.MatchCountSinceLastReport | Number of firewall rule matches since the last report. | long |
| crowdstrike.event.MobileAppsDetails | Provides one or more JSON objects describing the related mobile applications. | nested |
| crowdstrike.event.MobileDnsRequests | Provides one or more JSON objects describing the related DNS requests from the mobile device. | nested |
| crowdstrike.event.MobileNetworkConnections | Provides one or more JSON objects describing the related network connections from the mobile device. | nested |
| crowdstrike.event.MostRecentActivityTimeStamp | The timestamp of the latest activity performed by the account. | date |
| crowdstrike.event.MountedVolumes | Provides one or more JSON objects describing mounted volumes on the mobile device. | nested |
| crowdstrike.event.NetworkAccesses | Detected Network traffic done by a process. | nested |
| crowdstrike.event.NetworkProfile | CrowdStrike network profile. | keyword |
| crowdstrike.event.NotificationId | ID of the generated notification. | keyword |
| crowdstrike.event.NumberOfCompromisedEntities | Number of compromised entities, users and endpoints. | long |
| crowdstrike.event.NumbersOfAlerts | Number of alerts in the identity-based incident. | long |
| crowdstrike.event.OARuleInstanceID | Numerical ID of the custom IOA rule under a given CID. | keyword |
| crowdstrike.event.Objective | Method of detection. | keyword |
| crowdstrike.event.ObjectiveCRuntimesAltered | Provides one or more JSON objects describing the obj-c methods related to the malware. | nested |
| crowdstrike.event.OperationName | Event subtype. | keyword |
| crowdstrike.event.ParentImageFileName | The parent image file name involved. | keyword |
| crowdstrike.event.PatternDispositionFlags.BlockingUnsupportedOrDisabled |  | boolean |
| crowdstrike.event.PatternDispositionFlags.BootupSafeguardEnabled |  | boolean |
| crowdstrike.event.PatternDispositionFlags.CriticalProcessDisabled |  | boolean |
| crowdstrike.event.PatternDispositionFlags.Detect |  | boolean |
| crowdstrike.event.PatternDispositionFlags.FsOperationBlocked |  | boolean |
| crowdstrike.event.PatternDispositionFlags.HandleOperationDowngraded |  | boolean |
| crowdstrike.event.PatternDispositionFlags.InddetMask |  | boolean |
| crowdstrike.event.PatternDispositionFlags.Indicator |  | boolean |
| crowdstrike.event.PatternDispositionFlags.KillActionFailed |  | boolean |
| crowdstrike.event.PatternDispositionFlags.KillParent |  | boolean |
| crowdstrike.event.PatternDispositionFlags.KillProcess |  | boolean |
| crowdstrike.event.PatternDispositionFlags.KillSubProcess |  | boolean |
| crowdstrike.event.PatternDispositionFlags.OperationBlocked |  | boolean |
| crowdstrike.event.PatternDispositionFlags.PolicyDisabled |  | boolean |
| crowdstrike.event.PatternDispositionFlags.ProcessBlocked |  | boolean |
| crowdstrike.event.PatternDispositionFlags.QuarantineFile |  | boolean |
| crowdstrike.event.PatternDispositionFlags.QuarantineMachine |  | boolean |
| crowdstrike.event.PatternDispositionFlags.RegistryOperationBlocked |  | boolean |
| crowdstrike.event.PatternDispositionFlags.Rooting |  | boolean |
| crowdstrike.event.PatternDispositionFlags.SensorOnly |  | boolean |
| crowdstrike.event.PatternDispositionFlags.SuspendParent |  | boolean |
| crowdstrike.event.PatternDispositionFlags.SuspendProcess |  | boolean |
| crowdstrike.event.PatternDispositionValue | Unique ID associated with action taken. | integer |
| crowdstrike.event.PatternId | The numerical ID of the pattern associated with the action taken on the detection. | keyword |
| crowdstrike.event.PolicyID | CrowdStrike policy id. | keyword |
| crowdstrike.event.PolicyId | The ID of the associated Policy. | long |
| crowdstrike.event.PolicyName | CrowdStrike policy name. | keyword |
| crowdstrike.event.PrecedingActivityTimeStamp | The timestamp of the activity before the most recent activity was performed. | date |
| crowdstrike.event.PreviousPrivileges | A list of the source account's privileges before privilege changes were made. | keyword |
| crowdstrike.event.Protocol | CrowdStrike provided protocol. | keyword |
| crowdstrike.event.ProtocolAnomalyClassification | Authentication signature analysis. | keyword |
| crowdstrike.event.ResourceAttributes | A JSON blob with all resource attributes. | flattened |
| crowdstrike.event.ResourceId | The cloud resource identifier. | keyword |
| crowdstrike.event.ResourceIdType | The type of the detected resource identifier. | keyword |
| crowdstrike.event.ResourceName | Resource name if any. | keyword |
| crowdstrike.event.ResourceUrl | The URL to the cloud resource. | keyword |
| crowdstrike.event.RootAccessIndicators | Provides one or more JSON objects which includes logs and stack traces from the suspicious source. | nested |
| crowdstrike.event.RpcOpClassification | RPC operation type. | keyword |
| crowdstrike.event.RuleAction | Firewall rule action. | keyword |
| crowdstrike.event.RulePriority | Priority of the monitoring rule that found the match. | keyword |
| crowdstrike.event.SELinuxEnforcementPolicy | State of SELinux enforcement policy on an Android device. | keyword |
| crowdstrike.event.SHA1String | SHA1 sum of the executable associated with the detection. | keyword |
| crowdstrike.event.SHA256String | SHA256 sum of the executable associated with the detection. | keyword |
| crowdstrike.event.SafetyNetAdvice | Provides information to help explain why the Google SafetyNet Attestation API set eitherCTSProfileMatch or BasicIntegrity fields to false. | keyword |
| crowdstrike.event.SafetyNetBasicIntegrity | The result of a more lenient verdict for device integrity. | keyword |
| crowdstrike.event.SafetyNetCTSProfileMatch | The result of a stricter verdict for device integrity. | keyword |
| crowdstrike.event.SafetyNetErrorMessage | An encoded error message. | keyword |
| crowdstrike.event.SafetyNetErrors | Describes a SafetyNet error | keyword |
| crowdstrike.event.SafetyNetEvaluationType | Provides information about the type of measurements used to compute fields likeCTSProfileMatch and BasicIntegrity. | keyword |
| crowdstrike.event.ScanResults | Array of scan results. | nested |
| crowdstrike.event.ScheduledSearchExecutionId | ID of the specific search execution. | keyword |
| crowdstrike.event.ScheduledSearchId | Unique identifier of the associated scheduled search. | keyword |
| crowdstrike.event.ScheduledSearchUserId | User ID of the user that created the the associated scheduled search. | keyword |
| crowdstrike.event.ScheduledSearchUserUUID | UUID of the user that created the the associated scheduled search. | keyword |
| crowdstrike.event.SensorId | Unique ID associated with the Falcon sensor. | keyword |
| crowdstrike.event.ServiceName | Description of which related service was involved in the event. | keyword |
| crowdstrike.event.SessionId | Session ID of the remote response session. | keyword |
| crowdstrike.event.SeverityName | The severity level of the detection, as a string (High/Medium/Informational). | keyword |
| crowdstrike.event.SourceAccountUpn | Source user UPN. | keyword |
| crowdstrike.event.SourceEndpointAccountObjectGuid | Source endpoint object GUID | keyword |
| crowdstrike.event.SourceEndpointAccountObjectSid | Source endpoint object SID. | keyword |
| crowdstrike.event.SourceEndpointIpReputation | Source endpoint IP reputation. | keyword |
| crowdstrike.event.SourceEndpointSensorId | Source endpoint agent ID. | keyword |
| crowdstrike.event.SourceProducts | Names of the products from which the source data originated. | keyword |
| crowdstrike.event.SourceVendors | Names of the vendors from which the source data originated. | keyword |
| crowdstrike.event.SsoApplicationIdentifier | Destination application identifier. | keyword |
| crowdstrike.event.State | Identity-based detection or incident status. | keyword |
| crowdstrike.event.Status | CrowdStrike status. | keyword |
| crowdstrike.event.Success | Indicator of whether or not this event was successful. | boolean |
| crowdstrike.event.SuspiciousMachineAccountAlterationType | Machine alteration type. | keyword |
| crowdstrike.event.SystemProperties | Provides one or more JSON objects which includes related system properties. | nested |
| crowdstrike.event.Tags | Tags on the cloud resources if any. | nested |
| crowdstrike.event.TargetAccountDomain | Target user domain. | keyword |
| crowdstrike.event.TargetAccountName | Target user name. | keyword |
| crowdstrike.event.TargetAccountObjectSid | Target user object SID. | keyword |
| crowdstrike.event.TargetAccountUpn | Target user UPN. | keyword |
| crowdstrike.event.TargetEndpointAccountObjectGuid | Target endpoint object GUID. | keyword |
| crowdstrike.event.TargetEndpointAccountObjectSid | Target endpoint object SID. | keyword |
| crowdstrike.event.TargetEndpointHostName | Target endpoint hostname. | keyword |
| crowdstrike.event.TargetEndpointSensorId | Target endpoint agent ID. | keyword |
| crowdstrike.event.TargetServiceAccessIdentifier | Target SPN. | keyword |
| crowdstrike.event.Timestamp | Firewall rule triggered timestamp. | date |
| crowdstrike.event.Trampolines | Provides one or more JSON objects describing the relevant functions and processes performing inline API hooks. | nested |
| crowdstrike.event.TreeID | CrowdStrike tree id. | keyword |
| crowdstrike.event.UserId | Email address or user ID associated with the event. | keyword |
| crowdstrike.event.VerifiedBootState | Provides the device’s current boot state. | keyword |
| crowdstrike.event.XdrType | Type of detection: xdr or xdr-scheduled-search. | keyword |
| crowdstrike.metadata.customerIDString | Customer identifier | keyword |
| crowdstrike.metadata.eventType | DetectionSummaryEvent, FirewallMatchEvent, IncidentSummaryEvent, RemoteResponseSessionStartEvent, RemoteResponseSessionEndEvent, AuthActivityAuditEvent, or UserActivityAuditEvent | keyword |
| crowdstrike.metadata.offset | Offset number that tracks the location of the event in stream. This is used to identify unique detection events. | integer |
| crowdstrike.metadata.version | Schema version | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| device.id | The unique identifier of a device. The identifier must not change across application sessions but stay fixed for an instance of a (mobile) device.  On iOS, this value must be equal to the vendor identifier (https://developer.apple.com/documentation/uikit/uidevice/1620059-identifierforvendor). On Android, this value must be equal to the Firebase Installation ID or a globally unique UUID which is persisted across sessions in your application. For GDPR and data protection law reasons this identifier should not carry information that would allow to identify a user. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.end | `event.end` contains the date when the event ended or when the activity was last observed. | date |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.start | `event.start` contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| event.url | URL linking to an external system to continue investigation of this event. This URL links to another system where in-depth investigation of the specific occurrence of this event can take place. Alert events, indicated by `event.kind:alert`, are a common use case for this field. | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
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
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.end | The time the process ended. | date |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.parent.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.parent.command_line.text | Multi-field of `process.parent.command_line`. | match_only_text |
| process.parent.executable | Absolute path to the process executable. | keyword |
| process.parent.executable.text | Multi-field of `process.parent.executable`. | match_only_text |
| process.parent.pid | Process id. | long |
| process.pid | Process id. | long |
| process.start | The time the process started. | date |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.author | Name, organization, or pseudonym of the author or authors who created the rule used to generate this event. | keyword |
| rule.category | A categorization value keyword used by the entity using the rule for detection of this event. | keyword |
| rule.description | The description of the rule generating the event. | keyword |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| rule.ruleset | Name of the ruleset, policy, group, or parent category in which the rule used to generate this event is a member. | keyword |
| rule.uuid | A rule ID that is unique within the scope of a set or group of agents, observers, or other entities using the rule for detection of this event. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| threat.framework | Name of the threat framework used to further categorize and classify the tactic and technique of the reported threat. Framework classification can be provided by detecting systems, evaluated at ingest time, or retrospectively tagged to events. | keyword |
| threat.tactic.id | The id of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/ ) | keyword |
| threat.tactic.name | Name of the type of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/) | keyword |
| threat.technique.id | The id of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| threat.technique.name | The name of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| threat.technique.name.text | Multi-field of `threat.technique.name`. | match_only_text |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |


An example event for `falcon` looks as following:

```json
{
    "@timestamp": "2020-02-12T21:29:10.000Z",
    "agent": {
        "ephemeral_id": "6b7924ba-f695-422a-a296-d1092ff909e4",
        "id": "f25d13cd-18cc-4e73-822c-c4f849322623",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "crowdstrike": {
        "event": {
            "AuditKeyValues": [
                {
                    "Key": "APIClientID",
                    "ValueString": "1234567890abcdefghijklmnopqr"
                },
                {
                    "Key": "partition",
                    "ValueString": "0"
                },
                {
                    "Key": "offset",
                    "ValueString": "-1"
                },
                {
                    "Key": "appId",
                    "ValueString": "siem-connector-v2.0.0"
                },
                {
                    "Key": "eventType",
                    "ValueString": "[UserActivityAuditEvent HashSpreadingEvent RemoteResponseSessionStartEvent RemoteResponseSessionEndEvent DetectionSummaryEvent AuthActivityAuditEvent]"
                }
            ],
            "OperationName": "streamStarted",
            "Success": true
        },
        "metadata": {
            "customerIDString": "8f69fe9e-b995-4204-95ad-44f9bcf75b6b",
            "eventType": "AuthActivityAuditEvent",
            "offset": 0,
            "version": "1.0"
        }
    },
    "data_stream": {
        "dataset": "crowdstrike.falcon",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "f25d13cd-18cc-4e73-822c-c4f849322623",
        "snapshot": false,
        "version": "8.10.1"
    },
    "event": {
        "action": [
            "streamStarted"
        ],
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "created": "2020-02-12T21:29:10.710Z",
        "dataset": "crowdstrike.falcon",
        "ingested": "2023-09-26T13:19:10Z",
        "kind": "event",
        "original": "{\n    \"metadata\": {\n        \"customerIDString\": \"8f69fe9e-b995-4204-95ad-44f9bcf75b6b\",\n        \"offset\": 0,\n        \"eventType\": \"AuthActivityAuditEvent\",\n        \"eventCreationTime\": 1581542950710,\n        \"version\": \"1.0\"\n    },\n    \"event\": {\n        \"UserId\": \"api-client-id:1234567890abcdefghijklmnopqrstuvwxyz\",\n        \"UserIp\": \"10.10.0.8\",\n        \"OperationName\": \"streamStarted\",\n        \"ServiceName\": \"Crowdstrike Streaming API\",\n        \"Success\": true,\n        \"UTCTimestamp\": 1581542950,\n        \"AuditKeyValues\": [\n            {\n                \"Key\": \"APIClientID\",\n                \"ValueString\": \"1234567890abcdefghijklmnopqr\"\n            },\n            {\n                \"Key\": \"partition\",\n                \"ValueString\": \"0\"\n            },\n            {\n                \"Key\": \"offset\",\n                \"ValueString\": \"-1\"\n            },\n            {\n                \"Key\": \"appId\",\n                \"ValueString\": \"siem-connector-v2.0.0\"\n            },\n            {\n                \"Key\": \"eventType\",\n                \"ValueString\": \"[UserActivityAuditEvent HashSpreadingEvent RemoteResponseSessionStartEvent RemoteResponseSessionEndEvent DetectionSummaryEvent AuthActivityAuditEvent]\"\n            }\n        ]\n    }\n}",
        "outcome": "success"
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/falcon-audit-events.log"
        },
        "flags": [
            "multiline"
        ],
        "offset": 910
    },
    "message": "Crowdstrike Streaming API",
    "observer": {
        "product": "Falcon",
        "vendor": "Crowdstrike"
    },
    "related": {
        "ip": [
            "10.10.0.8"
        ],
        "user": [
            "api-client-id:1234567890abcdefghijklmnopqrstuvwxyz"
        ]
    },
    "source": {
        "ip": "10.10.0.8"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "crowdstrike-falcon"
    ],
    "user": {
        "name": "api-client-id:1234567890abcdefghijklmnopqrstuvwxyz"
    }
}
```

### FDR

The CrowdStrike Falcon Data Replicator (FDR) allows CrowdStrike users to replicate FDR data from CrowdStrike
managed S3 buckets. CrowdStrike writes notification events to a CrowdStrike managed SQS queue when new data is
available in S3.

This integration can be used in two ways. It can consume SQS notifications directly from the CrowdStrike managed
SQS queue or it can be used in conjunction with the FDR tool that replicates the data to a self-managed S3 bucket
and the integration can read from there.

In both cases SQS messages are deleted after they are processed. This allows you to operate more than one Elastic
Agent with this integration if needed and not have duplicate events, but it means you cannot ingest the data a second time.

#### Use with CrowdStrike managed S3/SQS

This is the simplest way to setup the integration, and also the default.

You need to set the integration up with the SQS queue URL provided by Crowdstrike FDR.
Ensure the `Is FDR queue` option is enabled.

#### Use with FDR tool and data replicated to a self-managed S3 bucket

This option can be used if you want to archive the raw CrowdStrike data.

You need to follow the steps below:

- Create a S3 bucket to receive the logs.
- Create a SQS queue.
- Configure your S3 bucket to send object created notifications to your SQS queue.
- Follow the [FDR tool](https://github.com/CrowdStrike/FDR) instructions to replicate data to your own S3 bucket.
- Configure the integration to read from your self-managed SQS topic.
- Disable the `Is FDR queue` option in the integration.

>  NOTE: While the FDR tool can replicate the files from S3 to your local file system, this integration cannot read those files because they are gzip compressed, and the log file input does not support reading compressed files.

#### Configuration for the S3 input

AWS credentials are required for running this integration if you want to use the S3 input.

##### Configuration parameters
* `access_key_id`: first part of access key.
* `secret_access_key`: second part of access key.
* `session_token`: required when using temporary security credentials.
* `credential_profile_name`: profile name in shared credentials file.
* `shared_credential_file`: directory of the shared credentials file.
* `endpoint`: URL of the entry point for an AWS web service.
* `role_arn`: AWS IAM Role to assume.

##### Credential Types
There are three types of AWS credentials can be used:

- access keys,
- temporary security credentials, and
- IAM role ARN.

##### Access keys

`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are the two parts of access keys.
They are long-term credentials for an IAM user, or the AWS account root user.
Please see [AWS Access Keys and Secret Access Keys](https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html#access-keys-and-secret-access-keys)
for more details.

##### Temporary security credentials

Temporary security credentials has a limited lifetime and consists of an
access key ID, a secret access key, and a security token which typically returned
from `GetSessionToken`.

MFA-enabled IAM users would need to submit an MFA code
while calling `GetSessionToken`. `default_region` identifies the AWS Region
whose servers you want to send your first API request to by default.

This is typically the Region closest to you, but it can be any Region. Please see
[Temporary Security Credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html)
for more details.

`sts get-session-token` AWS CLI can be used to generate temporary credentials.
For example. with MFA-enabled:
```js
aws> sts get-session-token --serial-number arn:aws:iam::1234:mfa/your-email@example.com --duration-seconds 129600 --token-code 123456
```

Because temporary security credentials are short term, after they expire, the
user needs to generate new ones and manually update the package configuration in
order to continue collecting `aws` metrics.

This will cause data loss if the configuration is not updated with new credentials before the old ones expire.

##### IAM role ARN

An IAM role is an IAM identity that you can create in your account that has
specific permissions that determine what the identity can and cannot do in AWS.

A role does not have standard long-term credentials such as a password or access
keys associated with it. Instead, when you assume a role, it provides you with
temporary security credentials for your role session.
IAM role Amazon Resource Name (ARN) can be used to specify which AWS IAM role to assume to generate
temporary credentials.

Please see [AssumeRole API documentation](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html) for more details.

##### Supported Formats
1. Use access keys: Access keys include `access_key_id`, `secret_access_key`
and/or `session_token`.
2. Use `role_arn`: `role_arn` is used to specify which AWS IAM role to assume
    for generating temporary credentials.
    If `role_arn` is given, the package will check if access keys are given.
    If not, the package will check for credential profile name.
    If neither is given, default credential profile will be used.

  Please make sure credentials are given under either a credential profile or
  access keys.
3. Use `credential_profile_name` and/or `shared_credential_file`:
    If `access_key_id`, `secret_access_key` and `role_arn` are all not given, then
    the package will check for `credential_profile_name`.
    If you use different credentials for different tools or applications, you can use profiles to
    configure multiple access keys in the same configuration file.
    If there is no `credential_profile_name` given, the default profile will be used.
    `shared_credential_file` is optional to specify the directory of your shared
    credentials file.
    If it's empty, the default directory will be used.
    In Windows, shared credentials file is at `C:\Users\<yourUserName>\.aws\credentials`.
    For Linux, macOS or Unix, the file locates at `~/.aws/credentials`.
    Please see[Create Shared Credentials File](https://docs.aws.amazon.com/ses/latest/DeveloperGuide/create-shared-credentials-file.html)
    for more details.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| crowdstrike.AccountType |  | keyword |
| crowdstrike.AgentIdString |  | keyword |
| crowdstrike.AgentLoadFlags |  | keyword |
| crowdstrike.AgentLocalTime |  | date |
| crowdstrike.AgentTimeOffset |  | float |
| crowdstrike.AgentVersion |  | keyword |
| crowdstrike.AllocateVirtualMemoryCount |  | long |
| crowdstrike.ApiReturnValue |  | keyword |
| crowdstrike.ArchiveFileWrittenCount |  | long |
| crowdstrike.AsepWrittenCount |  | long |
| crowdstrike.AssociatedFile |  | keyword |
| crowdstrike.AttemptNumber |  | long |
| crowdstrike.AuthenticationId |  | keyword |
| crowdstrike.AuthenticationPackage |  | keyword |
| crowdstrike.AuthenticationUuid |  | keyword |
| crowdstrike.AuthenticationUuidAsString |  | keyword |
| crowdstrike.BinaryExecutableWrittenCount |  | long |
| crowdstrike.BiosManufacturer |  | keyword |
| crowdstrike.BiosReleaseDate |  | date |
| crowdstrike.BiosVersion |  | keyword |
| crowdstrike.BootArgs |  | keyword |
| crowdstrike.BootTimeFunctionalityLevel |  | keyword |
| crowdstrike.BoundedCount |  | long |
| crowdstrike.BundleID |  | keyword |
| crowdstrike.CLICreationCount |  | long |
| crowdstrike.CallStackModuleNames |  | keyword |
| crowdstrike.CallStackModuleNamesVersion |  | version |
| crowdstrike.ChannelDiffStatus |  | keyword |
| crowdstrike.ChannelId |  | keyword |
| crowdstrike.ChannelVersion |  | keyword |
| crowdstrike.ChannelVersionRequired |  | keyword |
| crowdstrike.ChasisManufacturer |  | keyword |
| crowdstrike.ChassisType |  | keyword |
| crowdstrike.ClientComputerName |  | keyword |
| crowdstrike.CompletionEventId |  | keyword |
| crowdstrike.ConHostId |  | keyword |
| crowdstrike.ConHostProcessId |  | keyword |
| crowdstrike.ConfigBuild |  | keyword |
| crowdstrike.ConfigIDBase |  | keyword |
| crowdstrike.ConfigIDBuild |  | keyword |
| crowdstrike.ConfigIDPlatform |  | keyword |
| crowdstrike.ConfigStateData |  | keyword |
| crowdstrike.ConfigStateHash |  | keyword |
| crowdstrike.ConfigurationVersion |  | keyword |
| crowdstrike.ConnectTime |  | date |
| crowdstrike.ConnectType |  | keyword |
| crowdstrike.ConnectionFlags |  | keyword |
| crowdstrike.ContextProcessId |  | keyword |
| crowdstrike.CpuClockSpeed |  | keyword |
| crowdstrike.CpuFeaturesMask |  | keyword |
| crowdstrike.CpuProcessorName |  | keyword |
| crowdstrike.CpuSignature |  | keyword |
| crowdstrike.CpuVendor |  | keyword |
| crowdstrike.CreateProcessCount |  | long |
| crowdstrike.CreateProcessType |  | keyword |
| crowdstrike.CurrentFunctionalityLevel |  | keyword |
| crowdstrike.CurrentLocalIP |  | ip |
| crowdstrike.CustomerIdString |  | keyword |
| crowdstrike.CycleTime |  | long |
| crowdstrike.DesiredAccess |  | keyword |
| crowdstrike.DetectDescription |  | keyword |
| crowdstrike.DetectId |  | keyword |
| crowdstrike.DetectName |  | keyword |
| crowdstrike.DeviceId |  | keyword |
| crowdstrike.DirectoryCreatedCount |  | long |
| crowdstrike.DirectoryEnumeratedCount |  | long |
| crowdstrike.DnsRequestCount |  | long |
| crowdstrike.DocumentFileWrittenCount |  | long |
| crowdstrike.DownloadPath |  | keyword |
| crowdstrike.DownloadPort |  | long |
| crowdstrike.DownloadServer |  | keyword |
| crowdstrike.DualRequest |  | keyword |
| crowdstrike.ELFSubType |  | keyword |
| crowdstrike.EffectiveTransmissionClass |  | keyword |
| crowdstrike.EnabledPrivilegesBitmask |  | keyword |
| crowdstrike.EndTime |  | date |
| crowdstrike.Entitlements |  | keyword |
| crowdstrike.ErrorCode |  | keyword |
| crowdstrike.ErrorStatus |  | keyword |
| crowdstrike.EtwRawThreadId |  | long |
| crowdstrike.EventType |  | keyword |
| crowdstrike.EventUUID |  | keyword |
| crowdstrike.ExeAndServiceCount |  | long |
| crowdstrike.ExecutableDeletedCount |  | long |
| crowdstrike.ExternalApiType |  | keyword |
| crowdstrike.FXFileSize |  | keyword |
| crowdstrike.Facility |  | keyword |
| crowdstrike.FailedConnectCount |  | long |
| crowdstrike.FalconGroupingTags |  | keyword |
| crowdstrike.FalconHostLink |  | keyword |
| crowdstrike.FeatureExtractionVersion |  | keyword |
| crowdstrike.FeatureVector |  | keyword |
| crowdstrike.File |  | keyword |
| crowdstrike.FileAttributes |  | keyword |
| crowdstrike.FileDeletedCount |  | long |
| crowdstrike.FileEcpBitmask |  | keyword |
| crowdstrike.FileName |  | keyword |
| crowdstrike.FileObject |  | keyword |
| crowdstrike.FilePath |  | keyword |
| crowdstrike.FirmwareAnalysisEclConsumerInterfaceVersion |  | keyword |
| crowdstrike.FirmwareAnalysisEclControlInterfaceVersion |  | keyword |
| crowdstrike.FirstDiscoveredDate |  | date |
| crowdstrike.FirstSeen |  | date |
| crowdstrike.Flags |  | keyword |
| crowdstrike.GenericFileWrittenCount |  | long |
| crowdstrike.GrandParentBaseFileName |  | keyword |
| crowdstrike.GrandparentCommandLine |  | keyword |
| crowdstrike.GrandparentImageFileName |  | keyword |
| crowdstrike.HostGroups |  | keyword |
| crowdstrike.HostHiddenStatus |  | keyword |
| crowdstrike.IOCType |  | keyword |
| crowdstrike.IOCValue |  | keyword |
| crowdstrike.IOServiceClass |  | keyword |
| crowdstrike.IOServiceName |  | keyword |
| crowdstrike.IOServicePath |  | keyword |
| crowdstrike.ImageSubsystem |  | keyword |
| crowdstrike.InContext |  | keyword |
| crowdstrike.InDiscards |  | keyword |
| crowdstrike.InErrors |  | keyword |
| crowdstrike.InMulticastPkts |  | keyword |
| crowdstrike.InOctets |  | keyword |
| crowdstrike.InUcastPkts |  | keyword |
| crowdstrike.InUnknownProtos |  | keyword |
| crowdstrike.Information |  | keyword |
| crowdstrike.InjectedDllCount |  | long |
| crowdstrike.InjectedThreadCount |  | long |
| crowdstrike.IntegrityLevel |  | keyword |
| crowdstrike.InterfaceAlias |  | keyword |
| crowdstrike.InterfaceGuid |  | keyword |
| crowdstrike.InterfaceIndex |  | long |
| crowdstrike.InterfaceType |  | keyword |
| crowdstrike.InterfaceVersion |  | keyword |
| crowdstrike.IrpFlags |  | keyword |
| crowdstrike.IsOnNetwork |  | keyword |
| crowdstrike.IsOnRemovableDisk |  | keyword |
| crowdstrike.IsTransactedFile |  | keyword |
| crowdstrike.KernelTime |  | long |
| crowdstrike.LastDiscoveredBy |  | keyword |
| crowdstrike.LastLoggedOnHost |  | keyword |
| crowdstrike.LfoUploadFlags |  | keyword |
| crowdstrike.LightningLatencyState |  | keyword |
| crowdstrike.Line |  | keyword |
| crowdstrike.LocalAddressIP4 |  | ip |
| crowdstrike.LocalAddressIP6 |  | ip |
| crowdstrike.LocalAdminAccess |  | keyword |
| crowdstrike.LocalIP |  | ip |
| crowdstrike.LogicalCoreCount |  | long |
| crowdstrike.LoginSessionId |  | keyword |
| crowdstrike.LogoffTime |  | date |
| crowdstrike.LogonDomain |  | keyword |
| crowdstrike.LogonId |  | keyword |
| crowdstrike.LogonInfo |  | keyword |
| crowdstrike.LogonServer |  | keyword |
| crowdstrike.LogonTime |  | date |
| crowdstrike.LogonType |  | keyword |
| crowdstrike.MACAddress |  | keyword |
| crowdstrike.MACPrefix |  | keyword |
| crowdstrike.MD5String |  | keyword |
| crowdstrike.MLModelVersion |  | keyword |
| crowdstrike.MachOSubType |  | keyword |
| crowdstrike.MajorFunction |  | keyword |
| crowdstrike.MajorVersion |  | keyword |
| crowdstrike.Malicious |  | keyword |
| crowdstrike.MaxThreadCount |  | long |
| crowdstrike.MemoryTotal |  | keyword |
| crowdstrike.MicrocodeSignature |  | keyword |
| crowdstrike.MinorFunction |  | keyword |
| crowdstrike.MinorVersion |  | keyword |
| crowdstrike.MoboManufacturer |  | keyword |
| crowdstrike.MoboProductName |  | keyword |
| crowdstrike.ModelPrediction |  | keyword |
| crowdstrike.ModuleLoadCount |  | long |
| crowdstrike.NDRoot |  | keyword |
| crowdstrike.NeighborList |  | keyword |
| crowdstrike.NeighborName |  | keyword |
| crowdstrike.NetLuidIndex |  | long |
| crowdstrike.NetworkBindCount |  | long |
| crowdstrike.NetworkCapableAsepWriteCount |  | long |
| crowdstrike.NetworkCloseCount |  | long |
| crowdstrike.NetworkConnectCount |  | long |
| crowdstrike.NetworkConnectCountUdp |  | long |
| crowdstrike.NetworkContainmentState |  | keyword |
| crowdstrike.NetworkListenCount |  | long |
| crowdstrike.NetworkModuleLoadCount |  | long |
| crowdstrike.NetworkRecvAcceptCount |  | long |
| crowdstrike.NewExecutableWrittenCount |  | long |
| crowdstrike.NewFileIdentifier |  | keyword |
| crowdstrike.Nonce |  | integer |
| crowdstrike.OSVersionFileData |  | keyword |
| crowdstrike.OSVersionFileName |  | keyword |
| crowdstrike.OU |  | keyword |
| crowdstrike.Objective |  | keyword |
| crowdstrike.OperationFlags |  | keyword |
| crowdstrike.Options |  | keyword |
| crowdstrike.OutErrors |  | keyword |
| crowdstrike.OutMulticastPkts |  | keyword |
| crowdstrike.OutOctets |  | keyword |
| crowdstrike.OutUcastPkts |  | keyword |
| crowdstrike.Parameter1 |  | keyword |
| crowdstrike.Parameter2 |  | keyword |
| crowdstrike.Parameter3 |  | keyword |
| crowdstrike.ParentAuthenticationId |  | keyword |
| crowdstrike.ParentCommandLine |  | keyword |
| crowdstrike.ParentImageFileName |  | keyword |
| crowdstrike.PasswordLastSet |  | keyword |
| crowdstrike.PatternDispositionDescription |  | keyword |
| crowdstrike.PatternDispositionFlags.BlockingUnsupportedOrDisabled |  | boolean |
| crowdstrike.PatternDispositionFlags.BootupSafeguardEnabled |  | boolean |
| crowdstrike.PatternDispositionFlags.CriticalProcessDisabled |  | boolean |
| crowdstrike.PatternDispositionFlags.Detect |  | boolean |
| crowdstrike.PatternDispositionFlags.FsOperationBlocked |  | boolean |
| crowdstrike.PatternDispositionFlags.HandleOperationDowngraded |  | boolean |
| crowdstrike.PatternDispositionFlags.InddetMask |  | boolean |
| crowdstrike.PatternDispositionFlags.Indicator |  | boolean |
| crowdstrike.PatternDispositionFlags.KillActionFailed |  | boolean |
| crowdstrike.PatternDispositionFlags.KillParent |  | boolean |
| crowdstrike.PatternDispositionFlags.KillProcess |  | boolean |
| crowdstrike.PatternDispositionFlags.KillSubProcess |  | boolean |
| crowdstrike.PatternDispositionFlags.OperationBlocked |  | boolean |
| crowdstrike.PatternDispositionFlags.PolicyDisabled |  | boolean |
| crowdstrike.PatternDispositionFlags.ProcessBlocked |  | boolean |
| crowdstrike.PatternDispositionFlags.QuarantineFile |  | boolean |
| crowdstrike.PatternDispositionFlags.QuarantineMachine |  | boolean |
| crowdstrike.PatternDispositionFlags.RegistryOperationBlocked |  | boolean |
| crowdstrike.PatternDispositionFlags.Rooting |  | boolean |
| crowdstrike.PatternDispositionFlags.SensorOnly |  | boolean |
| crowdstrike.PatternDispositionFlags.SuspendParent |  | boolean |
| crowdstrike.PatternDispositionFlags.SuspendProcess |  | boolean |
| crowdstrike.PatternDispositionValue |  | long |
| crowdstrike.PciAttachmentState |  | keyword |
| crowdstrike.PhysicalAddress |  | keyword |
| crowdstrike.PhysicalAddressLength |  | long |
| crowdstrike.PhysicalCoreCount |  | long |
| crowdstrike.PointerSize |  | keyword |
| crowdstrike.PreviousConnectTime |  | date |
| crowdstrike.PrivilegedProcessHandleCount |  | long |
| crowdstrike.PrivilegesBitmask |  | keyword |
| crowdstrike.ProcessCount |  | long |
| crowdstrike.ProcessCreateFlags |  | keyword |
| crowdstrike.ProcessId |  | long |
| crowdstrike.ProcessParameterFlags |  | keyword |
| crowdstrike.ProcessSxsFlags |  | keyword |
| crowdstrike.ProcessorPackageCount |  | long |
| crowdstrike.ProductType |  | keyword |
| crowdstrike.ProtectVirtualMemoryCount |  | long |
| crowdstrike.ProvisionState |  | keyword |
| crowdstrike.PupAdwareConfidence |  | keyword |
| crowdstrike.PupAdwareDecisionValue |  | keyword |
| crowdstrike.QueueApcCount |  | long |
| crowdstrike.RFMState |  | keyword |
| crowdstrike.RGID |  | keyword |
| crowdstrike.RUID |  | keyword |
| crowdstrike.ReasonOfFunctionalityLevel |  | keyword |
| crowdstrike.RegKeySecurityDecreasedCount |  | long |
| crowdstrike.RemoteAccount |  | keyword |
| crowdstrike.RemovableDiskFileWrittenCount |  | long |
| crowdstrike.RequestType |  | keyword |
| crowdstrike.RpcClientProcessId |  | keyword |
| crowdstrike.RpcClientThreadId |  | keyword |
| crowdstrike.RpcNestingLevel |  | keyword |
| crowdstrike.RpcOpNum |  | keyword |
| crowdstrike.RunDllInvocationCount |  | long |
| crowdstrike.SHA1String |  | keyword |
| crowdstrike.SHA256String |  | keyword |
| crowdstrike.SVGID |  | keyword |
| crowdstrike.SVUID |  | keyword |
| crowdstrike.ScreenshotsTakenCount |  | long |
| crowdstrike.ScriptEngineInvocationCount |  | long |
| crowdstrike.SensorGroupingTags |  | keyword |
| crowdstrike.SensorId |  | keyword |
| crowdstrike.SensorStateBitMap |  | keyword |
| crowdstrike.ServiceDisplayName |  | keyword |
| crowdstrike.ServiceEventCount |  | long |
| crowdstrike.ServicePackMajor |  | keyword |
| crowdstrike.SessionId |  | keyword |
| crowdstrike.SessionProcessId |  | keyword |
| crowdstrike.SetThreadContextCount |  | long |
| crowdstrike.Severity |  | integer |
| crowdstrike.SeverityName |  | keyword |
| crowdstrike.ShareAccess |  | keyword |
| crowdstrike.SiteName |  | keyword |
| crowdstrike.Size |  | long |
| crowdstrike.SnapshotFileOpenCount |  | long |
| crowdstrike.SourceFileName |  | keyword |
| crowdstrike.SourceProcessId |  | keyword |
| crowdstrike.SourceThreadId |  | keyword |
| crowdstrike.StartTime |  | date |
| crowdstrike.Status |  | keyword |
| crowdstrike.SubStatus |  | keyword |
| crowdstrike.SuppressType |  | keyword |
| crowdstrike.SuspectStackCount |  | long |
| crowdstrike.SuspiciousCredentialModuleLoadCount |  | long |
| crowdstrike.SuspiciousDnsRequestCount |  | long |
| crowdstrike.SuspiciousFontLoadCount |  | long |
| crowdstrike.SuspiciousRawDiskReadCount |  | long |
| crowdstrike.SyntheticPR2Flags |  | keyword |
| crowdstrike.SystemManufacturer |  | keyword |
| crowdstrike.SystemProductName |  | keyword |
| crowdstrike.SystemSerialNumber |  | keyword |
| crowdstrike.SystemSku |  | keyword |
| crowdstrike.SystemTableIndex |  | long |
| crowdstrike.Tactic |  | keyword |
| crowdstrike.Tags |  | keyword |
| crowdstrike.TargetFileName |  | keyword |
| crowdstrike.TargetThreadId |  | keyword |
| crowdstrike.Technique |  | keyword |
| crowdstrike.Time |  | date |
| crowdstrike.Timeout |  | long |
| crowdstrike.TokenType |  | keyword |
| crowdstrike.USN |  | keyword |
| crowdstrike.UnixMode |  | keyword |
| crowdstrike.UnsignedModuleLoadCount |  | long |
| crowdstrike.UploadId |  | keyword |
| crowdstrike.User |  | keyword |
| crowdstrike.UserFlags |  | keyword |
| crowdstrike.UserGroupsBitmask |  | keyword |
| crowdstrike.UserLogoffType |  | keyword |
| crowdstrike.UserLogonFlags |  | keyword |
| crowdstrike.UserLogonFlags_decimal |  | keyword |
| crowdstrike.UserMemoryAllocateExecutableCount |  | long |
| crowdstrike.UserMemoryAllocateExecutableRemoteCount |  | long |
| crowdstrike.UserMemoryProtectExecutableCount |  | long |
| crowdstrike.UserMemoryProtectExecutableRemoteCount |  | long |
| crowdstrike.UserSid |  | keyword |
| crowdstrike.UserSid_readable |  | keyword |
| crowdstrike.UserTime |  | long |
| crowdstrike.VerifiedCertificate |  | keyword |
| crowdstrike.VnodeModificationType |  | keyword |
| crowdstrike.VnodeType |  | keyword |
| crowdstrike.VolumeAppearanceTime |  | keyword |
| crowdstrike.VolumeBusName |  | keyword |
| crowdstrike.VolumeBusPath |  | keyword |
| crowdstrike.VolumeDeviceCharacteristics |  | keyword |
| crowdstrike.VolumeDeviceInternal |  | keyword |
| crowdstrike.VolumeDeviceModel |  | keyword |
| crowdstrike.VolumeDeviceObjectFlags |  | keyword |
| crowdstrike.VolumeDevicePath |  | keyword |
| crowdstrike.VolumeDeviceProtocol |  | keyword |
| crowdstrike.VolumeDeviceRevision |  | keyword |
| crowdstrike.VolumeDeviceType |  | keyword |
| crowdstrike.VolumeDriveLetter |  | keyword |
| crowdstrike.VolumeFileSystemDevice |  | keyword |
| crowdstrike.VolumeFileSystemDriver |  | keyword |
| crowdstrike.VolumeFileSystemType |  | keyword |
| crowdstrike.VolumeIsEncrypted |  | keyword |
| crowdstrike.VolumeIsNetwork |  | keyword |
| crowdstrike.VolumeMediaBSDMajor |  | keyword |
| crowdstrike.VolumeMediaBSDMinor |  | keyword |
| crowdstrike.VolumeMediaBSDName |  | keyword |
| crowdstrike.VolumeMediaBSDUnit |  | keyword |
| crowdstrike.VolumeMediaContent |  | keyword |
| crowdstrike.VolumeMediaEjectable |  | keyword |
| crowdstrike.VolumeMediaName |  | keyword |
| crowdstrike.VolumeMediaPath |  | keyword |
| crowdstrike.VolumeMediaRemovable |  | keyword |
| crowdstrike.VolumeMediaSize |  | keyword |
| crowdstrike.VolumeMediaUUID |  | keyword |
| crowdstrike.VolumeMediaWhole |  | keyword |
| crowdstrike.VolumeMediaWritable |  | keyword |
| crowdstrike.VolumeMountPoint |  | keyword |
| crowdstrike.VolumeName |  | keyword |
| crowdstrike.VolumeRealDeviceName |  | keyword |
| crowdstrike.VolumeSectorSize |  | keyword |
| crowdstrike.VolumeType |  | keyword |
| crowdstrike.VolumeUUID |  | keyword |
| crowdstrike.WindowFlags |  | keyword |
| crowdstrike.__mv_LocalAddressIP4 |  | keyword |
| crowdstrike.__mv_aip |  | keyword |
| crowdstrike.__mv_discoverer_aid |  | keyword |
| crowdstrike.aipCount |  | integer |
| crowdstrike.cid |  | keyword |
| crowdstrike.discovererCount |  | integer |
| crowdstrike.discoverer_aid |  | keyword |
| crowdstrike.eid |  | integer |
| crowdstrike.info.host.\* | Host information enriched from aidmaster data. | object |
| crowdstrike.info.user.\* | User information enriched from userinfo data. | object |
| crowdstrike.localipCount |  | integer |
| crowdstrike.monthsincereset |  | keyword |
| crowdstrike.name |  | keyword |
| crowdstrike.subnet |  | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | keyword |
| dns.question.registered_domain | The highest registered domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| dns.question.subdomain | The subdomain is all of the labels under the registered_domain. If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| dns.question.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| dns.question.type | The type of record being queried. | keyword |
| dns.type | The type of DNS event captured, query or answer. If your source of DNS events only gives you DNS queries, you should only create dns events of type `dns.type:query`. If your source of DNS events gives you answers as well, you should create one event per query (optionally as soon as the query is seen). And a second event containing all query details as well as an array of answers. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.device | Device that is the source of the file. | keyword |
| file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| file.drive_letter | Drive letter where the file is located. This field is only relevant on Windows. The value should be uppercase, and not include the colon. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.inode | Inode representing the file in the filesystem. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| file.type | File type (file, dir, or symlink). | keyword |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.geo.city_name | City name. | keyword |
| host.geo.continent_name | Name of the continent. | keyword |
| host.geo.country_name | Country name. | keyword |
| host.geo.timezone | The time zone of the location, such as IANA time zone name. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.ip | Host ip addresses. | ip |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| host.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. If the OS you're dealing with is not listed as an expected value, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| input.type |  | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset |  | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.iana_number | IANA Protocol Number (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Standardized list of protocols. This aligns well with NetFlow and sFlow related logs which use the IANA Protocol Number. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| observer.address |  | keyword |
| observer.geo.city_name | City name. | keyword |
| observer.geo.continent_name | Name of the continent. | keyword |
| observer.geo.country_iso_code | Country ISO code. | keyword |
| observer.geo.country_name | Country name. | keyword |
| observer.geo.location | Longitude and latitude. | geo_point |
| observer.geo.region_iso_code | Region ISO code. | keyword |
| observer.geo.region_name | Region name. | keyword |
| observer.ip | IP addresses of the observer. | ip |
| observer.serial_number | Observer serial number. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| observer.version | Observer version. | keyword |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.end | The time the process ended. | date |
| process.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.exit_code | The exit code of the process, if this is a termination event. The field should be absent if there is no exit code for the event (e.g. process start). | long |
| process.hash.md5 | MD5 hash. | keyword |
| process.hash.sha256 | SHA256 hash. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.parent.name | Process name. Sometimes called program name or similar. | keyword |
| process.parent.name.text | Multi-field of `process.parent.name`. | match_only_text |
| process.pgid | Deprecated for removal in next major version release. This field is superseded by `process.group_leader.pid`. Identifier of the group of processes the process belongs to. | long |
| process.pid | Process id. | long |
| process.start | The time the process started. | date |
| process.thread.id | Thread ID. | long |
| process.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.title.text | Multi-field of `process.title`. | match_only_text |
| process.uptime | Seconds the process has been up. | long |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| server.address | Some event server addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| server.domain | The domain name of the server system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| server.registered_domain | The highest registered server domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| server.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| server.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.registered_domain | The highest registered url domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| url.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.full_name.text | Multi-field of `user.full_name`. | match_only_text |
| user.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |


An example event for `fdr` looks as following:

```json
{
    "@timestamp": "2020-10-01T09:58:32.519Z",
    "agent": {
        "ephemeral_id": "9eabd9f1-861b-4007-80d9-7ca2e4b6bb03",
        "id": "8e3dcae6-8d1c-46c1-bed0-bf69fdde05e5",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.11.1"
    },
    "crowdstrike": {
        "AuthenticationId": "3783389",
        "ConfigStateHash": "3998263252",
        "EffectiveTransmissionClass": "3",
        "Entitlements": "15",
        "ImageSubsystem": "2",
        "IntegrityLevel": "4096",
        "ParentAuthenticationId": "3783389",
        "ProcessCreateFlags": "525332",
        "ProcessParameterFlags": "16385",
        "ProcessSxsFlags": "1600",
        "RpcClientProcessId": "2439558094566",
        "SessionId": "1",
        "SourceProcessId": "2439558094566",
        "SourceThreadId": "77538684027214",
        "Tags": [
            "41",
            "12094627905582",
            "12094627906234"
        ],
        "TokenType": "2",
        "WindowFlags": "128",
        "cid": "ffffffff30a3407dae27d0503611022d",
        "info": {
            "host": {
                "AgentLoadFlags": "1",
                "AgentLocalTime": "1697775225",
                "AgentTimeOffset": "15889.017",
                "AgentVersion": "7.01.13922.0",
                "BiosManufacturer": "Iris",
                "BiosVersion": "vG17V.21040423/z64",
                "ChassisType": "Other",
                "City": "Chicago",
                "ConfigBuild": "1007.3.0017312.1",
                "ConfigIDBuild": "13922",
                "Continent": "North America",
                "Country": "United States of America",
                "FalconGroupingTags": "'FalconGroupingTags/AMERICA'",
                "FirstSeen": "1628678052.0",
                "HostHiddenStatus": "Visible",
                "MachineDomain": "groot.org",
                "OU": "Servers;America;Offices",
                "PointerSize": "8",
                "ProductType": "3.0",
                "ServicePackMajor": "0",
                "SiteName": "BCL",
                "SystemManufacturer": "Iris",
                "SystemProductName": "IrOS",
                "Time": "1697992719.22",
                "Timezone": "America/Chicago",
                "Version": "Windows Server 2021",
                "cid": "ffffffff30a3407dae27d0503611022d",
                "event_platform": "Win"
            },
            "user": {
                "AccountType": "Domain User",
                "LastLoggedOnHost": "COMPUTER1",
                "LocalAdminAccess": "No",
                "LogonInfo": "Domain User Logon",
                "LogonTime": "1702546155.197",
                "LogonType": "Interactive",
                "PasswordLastSet": "1699971198.062",
                "User": "DOMAIN\\BRADLEYA",
                "UserIsAdmin": "0",
                "UserLogonFlags_decimal": "0",
                "_time": "1702546168.576",
                "cid": "ffffffff15754bcfb5f9152ec7ac90ac",
                "event_platform": "Win",
                "monthsincereset": "1.0"
            }
        },
        "name": "ProcessRollup2V18"
    },
    "data_stream": {
        "dataset": "crowdstrike.fdr",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "8e3dcae6-8d1c-46c1-bed0-bf69fdde05e5",
        "snapshot": false,
        "version": "8.11.1"
    },
    "event": {
        "action": "ProcessRollup2",
        "agent_id_status": "verified",
        "category": [
            "process"
        ],
        "created": "2020-10-01T09:58:32.519Z",
        "dataset": "crowdstrike.fdr",
        "id": "ffffffff-1111-11eb-8462-02ade3b2f949",
        "ingested": "2023-12-19T11:18:43Z",
        "kind": "event",
        "original": "{\"AuthenticationId\":\"3783389\",\"CommandLine\":\"\\\"C:\\\\WINDOWS\\\\system32\\\\backgroundTaskHost.exe\\\" -ServerName:App.AppXnme9zjyebb2xnyygh6q9ev6p5d234br2.mca\",\"ConfigBuild\":\"1007.3.0012309.1\",\"ConfigStateHash\":\"3998263252\",\"EffectiveTransmissionClass\":\"3\",\"Entitlements\":\"15\",\"ImageFileName\":\"\\\\Device\\\\HarddiskVolume3\\\\Windows\\\\System32\\\\backgroundTaskHost.exe\",\"ImageSubsystem\":\"2\",\"IntegrityLevel\":\"4096\",\"MD5HashData\":\"50d5fd1290d94d46acca0585311e74d5\",\"ParentAuthenticationId\":\"3783389\",\"ParentBaseFileName\":\"svchost.exe\",\"ParentProcessId\":\"2439558094566\",\"ProcessCreateFlags\":\"525332\",\"ProcessEndTime\":\"\",\"ProcessParameterFlags\":\"16385\",\"ProcessStartTime\":\"1604855181.648\",\"ProcessSxsFlags\":\"1600\",\"RawProcessId\":\"22272\",\"RpcClientProcessId\":\"2439558094566\",\"SHA1HashData\":\"0000000000000000000000000000000000000000\",\"SHA256HashData\":\"b8e176fe76a1454a00c4af0f8bf8870650d9c33d3e333239a59445c5b35c9a37\",\"SessionId\":\"1\",\"SourceProcessId\":\"2439558094566\",\"SourceThreadId\":\"77538684027214\",\"Tags\":\"41, 12094627905582, 12094627906234\",\"TargetProcessId\":\"2450046082233\",\"TokenType\":\"2\",\"UserSid\":\"S-1-12-1-3697283754-1083485977-2164330645-2516515886\",\"WindowFlags\":\"128\",\"aid\":\"ffffffff655344736aca58d17fb570f0\",\"aip\":\"67.43.156.14\",\"cid\":\"ffffffff30a3407dae27d0503611022d\",\"event_platform\":\"Win\",\"event_simpleName\":\"ProcessRollup2\",\"id\":\"ffffffff-1111-11eb-8462-02ade3b2f949\",\"name\":\"ProcessRollup2V18\",\"timestamp\":\"1601546312519\"}",
        "outcome": "success",
        "timezone": "+00:00",
        "type": [
            "start"
        ]
    },
    "host": {
        "ip": [
            "16.15.12.10"
        ],
        "name": "FEVWSN1-234",
        "os": {
            "type": "windows"
        }
    },
    "input": {
        "type": "aws-s3"
    },
    "log": {
        "file": {
            "path": "https://elastic-package-crowdstrike-fdr-12701.s3.us-east-1.amazonaws.com/data"
        },
        "offset": 107991
    },
    "observer": {
        "address": [
            "67.43.156.14"
        ],
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": [
            "67.43.156.14"
        ],
        "serial_number": "ffffffff655344736aca58d17fb570f0",
        "type": "agent",
        "vendor": "crowdstrike",
        "version": "1007.3.0012309.1"
    },
    "process": {
        "args": [
            "C:\\WINDOWS\\system32\\backgroundTaskHost.exe",
            "-ServerName:App.AppXnme9zjyebb2xnyygh6q9ev6p5d234br2.mca"
        ],
        "args_count": 2,
        "command_line": "\"C:\\WINDOWS\\system32\\backgroundTaskHost.exe\" -ServerName:App.AppXnme9zjyebb2xnyygh6q9ev6p5d234br2.mca",
        "entity_id": "2450046082233",
        "executable": "\\Device\\HarddiskVolume3\\Windows\\System32\\backgroundTaskHost.exe",
        "hash": {
            "md5": "50d5fd1290d94d46acca0585311e74d5",
            "sha256": "b8e176fe76a1454a00c4af0f8bf8870650d9c33d3e333239a59445c5b35c9a37"
        },
        "name": "backgroundTaskHost.exe",
        "parent": {
            "entity_id": "2439558094566",
            "name": "svchost.exe"
        },
        "pid": 22272,
        "start": "2020-11-08T17:06:21.648Z"
    },
    "related": {
        "hash": [
            "50d5fd1290d94d46acca0585311e74d5",
            "b8e176fe76a1454a00c4af0f8bf8870650d9c33d3e333239a59445c5b35c9a37",
            "3998263252"
        ],
        "hosts": [
            "FEVWSN1-234",
            "COMPUTER1"
        ],
        "ip": [
            "67.43.156.14",
            "16.15.12.10"
        ],
        "user": [
            "Alan-One",
            "DOMAIN\\BRADLEYA"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "crowdstrike-fdr"
    ],
    "url": {
        "scheme": "http"
    },
    "user": {
        "id": "S-1-12-1-3697283754-1083485977-2164330645-2516515886",
        "name": "Alan-One"
    }
}
```
