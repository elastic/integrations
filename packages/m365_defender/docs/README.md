# M365 Defender integration

This integration is for M365 Defender logs, previously known as Threat Protection.

## Configuration

To configure access for Elastic Agent to communicate with Microsoft 365 Defender you will have to create a new Azure Application registration, this will again return OAuth tokens with access to the Microsoft 365 Defender API.

The procedure to create an application is found on the below link:

[Create a new Azure Application](https://docs.microsoft.com/en-us/microsoft-365/security/mtp/api-create-app-web?view=o365-worldwide#create-an-app)

When giving the application the API permissions described in the documentation (Incident.Read.All) it will only grant access to read Incidents from 365 Defender and nothing else in the Azure Domain.

After the application has been created, it should contain 3 values that you need to apply to the module configuration.

These values are:

- Client ID
- Client Secret
- Tenant ID

An example event for `log` looks as following:

```json
{
    "@timestamp": "2020-09-06T12:07:55.32Z",
    "agent": {
        "ephemeral_id": "73d632b1-bafb-4800-b431-b8180297db7d",
        "id": "b4a8802d-e9ee-4bd6-9364-9d68f840d4e0",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "cloud": {
        "provider": "azure"
    },
    "data_stream": {
        "dataset": "m365_defender.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "b4a8802d-e9ee-4bd6-9364-9d68f840d4e0",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "action": "InitialAccess",
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "created": "2020-09-06T12:07:55.1366667Z",
        "dataset": "m365_defender.log",
        "duration": 0,
        "end": "2020-09-06T12:04:00Z",
        "id": "faf8edc936-85f8-a603-b800-08d8525cf099",
        "ingested": "2022-03-22T08:22:25Z",
        "kind": "alert",
        "provider": "OfficeATP",
        "severity": 1,
        "start": "2020-09-06T12:04:00Z",
        "timezone": "UTC"
    },
    "file": {
        "hash": {}
    },
    "input": {
        "type": "httpjson"
    },
    "m365_defender": {
        "alerts": {
            "assignedTo": "Automation",
            "creationTime": "2020-09-06T12:07:54.3716642Z",
            "detectionSource": "OfficeATP",
            "entities": {
                "entityType": "MailBox",
                "mailboxAddress": "testUser3@contoso.com",
                "mailboxDisplayName": "test User3"
            },
            "incidentId": "924518",
            "investigationState": "Queued",
            "lastUpdatedTime": "2020-09-06T12:37:40.88Z",
            "severity": "Informational",
            "status": "InProgress"
        },
        "classification": "Unknown",
        "determination": "NotAvailable",
        "incidentId": "924518",
        "incidentName": "Email reported by user as malware or phish",
        "status": "Active"
    },
    "message": "Email reported by user as malware or phish",
    "observer": {
        "name": "OfficeATP",
        "product": "365 Defender",
        "vendor": "Microsoft"
    },
    "process": {
        "parent": {}
    },
    "related": {
        "user": [
            "testUser3@contoso.com"
        ]
    },
    "rule": {
        "description": "This alert is triggered when any email message is reported as malware or phish by users -V1.0.0.2"
    },
    "tags": [
        "m365_defender",
        "forwarded"
    ],
    "threat": {
        "framework": "MITRE ATT\u0026CK",
        "technique": {
            "name": "InitialAccess"
        }
    },
    "user": {
        "name": "testUser3@contoso.com"
    }
}
```

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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
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
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| m365_defender.alerts.actorName | The activity group, if any, the associated with this alert. | keyword |
| m365_defender.alerts.assignedTo | Owner of the incident, or null if no owner is assigned. | keyword |
| m365_defender.alerts.classification | The specification for the incident. The property values are: Unknown, FalsePositive, TruePositive or null. | keyword |
| m365_defender.alerts.creationTime | Time when alert was first created. | date |
| m365_defender.alerts.detectionSource | The service that initially detected the threat. | keyword |
| m365_defender.alerts.determination | Specifies the determination of the incident. The property values are: NotAvailable, Apt, Malware, SecurityPersonnel, SecurityTesting, UnwantedSoftware, Other or null | keyword |
| m365_defender.alerts.devices | The devices related to the investigation. | flattened |
| m365_defender.alerts.entities.accountName | Account name of the related user. | keyword |
| m365_defender.alerts.entities.clusterBy | A list of metadata if the entityType is MailCluster. | keyword |
| m365_defender.alerts.entities.deliveryAction | The delivery status for the related email message. | keyword |
| m365_defender.alerts.entities.deviceId | The unique ID of the device related to the event. | keyword |
| m365_defender.alerts.entities.entityType | Entities that have been identified to be part of, or related to, a given alert. The properties values are: User, Ip, Url, File, Process, MailBox, MailMessage, MailCluster, Registry. | keyword |
| m365_defender.alerts.entities.ipAddress | The related IP address to the event. | keyword |
| m365_defender.alerts.entities.mailboxAddress | The mail address of the related mailbox. | keyword |
| m365_defender.alerts.entities.mailboxDisplayName | The display name of the related mailbox. | keyword |
| m365_defender.alerts.entities.recipient | The recipient for the related email message. | keyword |
| m365_defender.alerts.entities.registryHive | Reference to which Hive in registry the event is related to, if eventType is registry. Example: HKEY_LOCAL_MACHINE. | keyword |
| m365_defender.alerts.entities.registryKey | Reference to the related registry key to the event. | keyword |
| m365_defender.alerts.entities.registryValueType | Value type of the registry key/value pair related to the event. | keyword |
| m365_defender.alerts.entities.securityGroupId | The Security Group ID for the user related to the email message. | keyword |
| m365_defender.alerts.entities.securityGroupName | The Security Group Name for the user related to the email message. | keyword |
| m365_defender.alerts.entities.sender | The sender for the related email message. | keyword |
| m365_defender.alerts.entities.subject | The subject for the related email message. | keyword |
| m365_defender.alerts.incidentId | Unique identifier to represent the incident this alert is associated with. | keyword |
| m365_defender.alerts.investigationId | The automated investigation id triggered by this alert. | keyword |
| m365_defender.alerts.investigationState | Information on the investigation's current status. | keyword |
| m365_defender.alerts.lastUpdatedTime | Time when alert was last updated. | date |
| m365_defender.alerts.mitreTechniques | The attack techniques, as aligned with the MITRE ATT&CK™ framework. | keyword |
| m365_defender.alerts.resolvedTime | Time when alert was resolved. | date |
| m365_defender.alerts.severity | The severity of the related alert. | keyword |
| m365_defender.alerts.status | Categorize alerts (as New, Active, or Resolved). | keyword |
| m365_defender.alerts.threatFamilyName | Threat family associated with this alert. | keyword |
| m365_defender.alerts.userSid | The SID of the related user | keyword |
| m365_defender.assignedTo | Owner of the alert. | keyword |
| m365_defender.classification | Specification of the alert. Possible values are: 'Unknown', 'FalsePositive', 'TruePositive'. | keyword |
| m365_defender.comments | Comments attached to the related incident. | keyword |
| m365_defender.determination | Specifies the determination of the incident. The property values are: NotAvailable, Apt, Malware, SecurityPersonnel, SecurityTesting, UnwantedSoftware, Other. | keyword |
| m365_defender.incidentId | Unique identifier to represent the incident. | keyword |
| m365_defender.incidentName | Name of the Incident. | keyword |
| m365_defender.investigationState | The current state of the Investigation. | keyword |
| m365_defender.redirectIncidentId | Only populated in case an incident is being grouped together with another incident, as part of the incident processing logic. | keyword |
| m365_defender.status | Specifies the current status of the alert. Possible values are: 'Unknown', 'New', 'InProgress' and 'Resolved'. | keyword |
| m365_defender.tags | Array of custom tags associated with an incident, for example to flag a group of incidents with a common characteristic. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| observer.name | Custom name of the observer. This is a name that can be given to an observer. This can be helpful for example if multiple firewalls of the same model are used in an organization. If no custom name is needed, the field can be left empty. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.parent.pid | Process id. | long |
| process.parent.start | The time the process started. | date |
| process.pid | Process id. | long |
| process.start | The time the process started. | date |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.description | The description of the rule generating the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| threat.framework | Name of the threat framework used to further categorize and classify the tactic and technique of the reported threat. Framework classification can be provided by detecting systems, evaluated at ingest time, or retrospectively tagged to events. | keyword |
| threat.technique.name | The name of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| threat.technique.name.text | Multi-field of `threat.technique.name`. | match_only_text |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.full.text | Multi-field of `url.full`. | match_only_text |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |

