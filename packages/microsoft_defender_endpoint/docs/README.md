# Microsoft Defender for Endpoint integration

This integration is for Microsoft Defender for Endpoint logs.

To allow the integration to ingest data from the Microsoft Defender API, you need to create a new application on your Azure domain. The procedure to create an application is found on the [Create a new Azure Application](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/exposed-apis-create-app-webapp) documentation page.

When giving the application the API permissions described in the documentation (`Windows Defender ATP Alert.Read.All`) it will only grant access to read alerts from ATP and nothing else in the Azure Domain.

After the application has been created, it should contain 3 values that you need to apply to the module configuration.

These values are:

- Client ID
- Client Secret
- Tenant ID

## ECS mappings

| Defender for Endpoint fields        | ECS Fields                     |
|-------------------------------------|--------------------------------|
| alertCreationTime                   | @timestamp                     |
| aadTenantId                         | cloud.account.id               |
| category                            | threat.technique.name          |
| computerDnsName                     | host.hostname                  |
| description                         | rule.description               |
| detectionSource                     | observer.name                  |
| evidence.fileName                   | file.name                      |
| evidence.filePath                   | file.path                      |
| evidence.processId                  | process.pid                    |
| evidence.processCommandLine         | process.command_line           |
| evidence.processCreationTime        | process.start                  |
| evidence.parentProcessId            | process.parent.pid             |
| evidence.parentProcessCreationTime  | process.parent.start           |
| evidence.sha1                       | file.hash.sha1                 |
| evidence.sha256                     | file.hash.sha256               |
| evidence.url                        | url.full                       |
| firstEventTime                      | event.start                    |
| id                                  | event.id                       |
| lastEventTime                       | event.end                      |
| machineId                           | cloud.instance.id              |
| relatedUser.userName                | host.user.name                 |
| relatedUser.domainName              | host.user.domain               |
| title                               | message                        |
| severity                            | event.severity                 |

An example event for `log` looks as following:

```json
{
    "rule": {
        "description": "Malware and unwanted software are undesirable applications that perform annoying, disruptive, or harmful actions on affected machines. Some of these undesirable applications can replicate and spread from one machine to another. Others are able to receive commands from remote attackers and perform activities associated with cyber attacks.\n\nA malware is considered active if it is found running on the machine or it already has persistence mechanisms in place. Active malware detections are assigned higher severity ratings.\n\nBecause this malware was active, take precautionary measures and check for residual signs of infection."
    },
    "message": "An active 'Exeselrun' malware was detected",
    "microsoft": {
        "defender_endpoint": {
            "investigationId": "9",
            "evidence": {
                "entityType": "File"
            },
            "resolvedTime": "2020-06-30T11:13:12.2680434Z",
            "investigationState": "Benign",
            "incidentId": "12",
            "assignedTo": "elastic@elasticuser.com",
            "lastUpdateTime": "2020-07-03T15:15:39.13Z",
            "status": "Resolved"
        }
    },
    "cloud": {
        "provider": "azure",
        "account": {
            "id": "123543-d66c-4c7e-9e30-40034eb7c6f3"
        },
        "instance": {
            "id": "c5a964f417c11f6277d5bf9489f0d"
        }
    },
    "observer": {
        "name": "WindowsDefenderAv",
        "product": "Defender ATP",
        "vendor": "Microsoft"
    },
    "file": {
        "name": "SB.xsl",
        "path": "C:\\Windows\\Temp\\sb-sim-temp-ikyxqi\\sb_10554_bs_h4qpk5"
    },
    "related": {
        "hosts": [
            "testserver4"
        ]
    },
    "host": {
        "name": "testserver4",
        "hostname": "testserver4"
    },
    "threat": {
        "technique": {
            "name": "Malware"
        },
        "framework": "MITRE ATT\u0026CK"
    },
    "event": {
        "severity": 2,
        "kind": "alert",
        "timezone": "UTC",
        "created": "2020-06-30T10:09:01.1569718Z",
        "start": "2020-06-30T10:07:44.333733Z",
        "type": [
            "end"
        ],
        "duration": 0,
        "ingested": "2021-02-18T13:34:35.126958300Z",
        "provider": "defender_endpoint",
        "action": "Malware",
        "end": "2020-06-30T10:07:44.333733Z",
        "id": "da637291085411733957_-1043898914",
        "category": [
            "host",
            "malware"
        ]
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
| container.image.tag | Container image tags. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.hash.sha512 | SHA512 hash. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
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
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.logger | The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name. | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| microsoft.defender_endpoint.assignedTo | Owner of the alert. | keyword |
| microsoft.defender_endpoint.classification | Specification of the alert. Possible values are: 'Unknown', 'FalsePositive', 'TruePositive'. | keyword |
| microsoft.defender_endpoint.determination | Specifies the determination of the alert. Possible values are: 'NotAvailable', 'Apt', 'Malware', 'SecurityPersonnel', 'SecurityTesting', 'UnwantedSoftware', 'Other'. | keyword |
| microsoft.defender_endpoint.evidence.aadUserId | ID of the user involved in the alert | keyword |
| microsoft.defender_endpoint.evidence.accountName | Username of the user involved in the alert | keyword |
| microsoft.defender_endpoint.evidence.domainName | Domain name related to the alert | keyword |
| microsoft.defender_endpoint.evidence.entityType | The type of evidence | keyword |
| microsoft.defender_endpoint.evidence.ipAddress | IP address involved in the alert | ip |
| microsoft.defender_endpoint.evidence.userPrincipalName | Principal name of the user involved in the alert | keyword |
| microsoft.defender_endpoint.incidentId | The Incident ID of the Alert. | keyword |
| microsoft.defender_endpoint.investigationId | The Investigation ID related to the Alert. | keyword |
| microsoft.defender_endpoint.investigationState | The current state of the Investigation. | keyword |
| microsoft.defender_endpoint.lastUpdateTime | The date and time (in UTC) the alert was last updated. | date |
| microsoft.defender_endpoint.rbacGroupName | User group related to the alert | keyword |
| microsoft.defender_endpoint.resolvedTime | The date and time in which the status of the alert was changed to 'Resolved'. | date |
| microsoft.defender_endpoint.status | Specifies the current status of the alert. Possible values are: 'Unknown', 'New', 'InProgress' and 'Resolved'. | keyword |
| microsoft.defender_endpoint.threatFamilyName | Threat family. | keyword |
| observer.name | Custom name of the observer. This is a name that can be given to an observer. This can be helpful for example if multiple firewalls of the same model are used in an organization. If no custom name is needed, the field can be left empty. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
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
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |

