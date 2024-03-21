# Microsoft Defender for Endpoint integration

This integration is for [Microsoft Defender for Endpoint](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-endpoint?view=o365-worldwide) logs.

## Setting up

To allow the integration to ingest data from the Microsoft Defender API, you need to create a new application on your Azure domain. The procedure to create an application is found on the [Create a new Azure Application](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/exposed-apis-create-app-webapp) documentation page.

> Note: When giving the application the API permissions described in the documentation (`Windows Defender ATP Alert.Read.All`), it will only grant access to read alerts from ATP and nothing else in the Azure Domain

After the application has been created, it should contain 3 values that you need to apply to the module configuration.

These values are:

- Client ID
- Client Secret
- Tenant ID

## ECS mappings

| Defender for Endpoint fields       | ECS Fields            |
| ---------------------------------- | --------------------- |
| alertCreationTime                  | @timestamp            |
| aadTenantId                        | cloud.account.id      |
| category                           | threat.technique.name |
| computerDnsName                    | host.hostname         |
| description                        | rule.description      |
| detectionSource                    | observer.name         |
| evidence.fileName                  | file.name             |
| evidence.filePath                  | file.path             |
| evidence.processId                 | process.pid           |
| evidence.processCommandLine        | process.command_line  |
| evidence.processCreationTime       | process.start         |
| evidence.parentProcessId           | process.parent.pid    |
| evidence.parentProcessCreationTime | process.parent.start  |
| evidence.sha1                      | file.hash.sha1        |
| evidence.sha256                    | file.hash.sha256      |
| evidence.url                       | url.full              |
| firstEventTime                     | event.start           |
| id                                 | event.id              |
| lastEventTime                      | event.end             |
| machineId                          | cloud.instance.id     |
| title                              | message               |
| severity                           | event.severity        |

An example event for `log` looks as following:

```json
{
    "@timestamp": "2023-09-22T03:31:55.887Z",
    "agent": {
        "ephemeral_id": "20bd2ad7-6c7e-4d34-9d55-57edc09ba1a6",
        "id": "a4d1a8b2-b45c-4d97-a37a-bd371f13111b",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.8.1"
    },
    "cloud": {
        "account": {
            "id": "a839b112-1253-6432-9bf6-94542403f21c"
        },
        "instance": {
            "id": "111e6dd8c833c8a052ea231ec1b19adaf497b625"
        },
        "provider": "azure"
    },
    "data_stream": {
        "dataset": "microsoft_defender_endpoint.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "a4d1a8b2-b45c-4d97-a37a-bd371f13111b",
        "snapshot": false,
        "version": "8.8.1"
    },
    "event": {
        "action": "Execution",
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "created": "2021-01-26T20:33:57.7220239Z",
        "dataset": "microsoft_defender_endpoint.log",
        "duration": 101466100,
        "end": "2021-01-26T20:31:33.0577322Z",
        "id": "da637472900382838869_1364969609",
        "ingested": "2023-09-22T03:31:58Z",
        "kind": "alert",
        "provider": "defender_endpoint",
        "severity": 2,
        "start": "2021-01-26T20:31:32.9562661Z",
        "timezone": "UTC",
        "type": [
            "access",
            "start"
        ]
    },
    "host": {
        "hostname": "temp123.middleeast.corp.microsoft.com",
        "name": "temp123.middleeast.corp.microsoft.com"
    },
    "input": {
        "type": "httpjson"
    },
    "message": "Low-reputation arbitrary code executed by signed executable",
    "microsoft": {
        "defender_endpoint": {
            "evidence": {
                "aadUserId": "11118379-2a59-1111-ac3c-a51eb4a3c627",
                "accountName": "name",
                "domainName": "DOMAIN",
                "entityType": "User",
                "userPrincipalName": "temp123@microsoft.com"
            },
            "incidentId": "1126093",
            "investigationState": "Queued",
            "lastUpdateTime": "2021-01-26T20:33:59.2Z",
            "rbacGroupName": "A",
            "status": "New"
        }
    },
    "observer": {
        "name": "WindowsDefenderAtp",
        "product": "Defender for Endpoint",
        "vendor": "Microsoft"
    },
    "related": {
        "hosts": [
            "temp123.middleeast.corp.microsoft.com"
        ],
        "user": [
            "temp123"
        ]
    },
    "rule": {
        "description": "Binaries signed by Microsoft can be used to run low-reputation arbitrary code. This technique hides the execution of malicious code within a trusted process. As a result, the trusted process might exhibit suspicious behaviors, such as opening a listening port or connecting to a command-and-control (C&C) server."
    },
    "tags": [
        "microsoft-defender-endpoint",
        "forwarded"
    ],
    "threat": {
        "framework": "MITRE ATT&CK",
        "technique": {
            "name": [
                "Execution"
            ]
        }
    },
    "user": {
        "domain": "DOMAIN",
        "id": "S-1-5-21-11111607-1111760036-109187956-75141",
        "name": "temp123"
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
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If `event.start` and `event.end` are known this value should be the difference between the end and start time. | long |
| event.end | `event.end` contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.start | `event.start` contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.hash.sha512 | SHA512 hash. | keyword |
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
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |

