# Azure Eventhub Input

The Azure Eventhub Input integration allows users to collect events from Azure event hubs.
 The azure-eventhub input functionality is based on the the event processor host (EPH is intended to be run across multiple processes and machines while load balancing message consumers more on this here https://github.com/Azure/azure-event-hubs-go#event-processor-host, https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-event-processor-host). State such as leases on partitions and checkpoints in the event stream are shared between receivers using an Azure Storage container. 
 For this reason, as a prerequisite to using this input, users will have to create or use an existing storage account.

There are several requirements before using the integration since the logs will actually be read from azure event hubs.
   * the logs/metrics have to be exported first to the event hub https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-create-kafka-enabled

## Settings

`eventhub` :
  _string_
It is a fully managed, real-time data ingestion service. Elastic recommends using only letters, numbers, and the hyphen (-) character for Event Hub names to maximize compatibility. You can use existing Event Hubs having underscores (_) in the Event Hub name; in this case, the integration will replace underscores with hyphens (-) when it uses the Event Hub name to create dependent Azure resources behind the scenes (e.g., the storage account container to store Event Hub consumer offsets). Elastic also recommends using a separate event hub for each log type as the field mappings of each log type differ.

`consumer_group` :
_string_
 The publish/subscribe mechanism of Event Hubs is enabled through consumer groups. A consumer group is a view (state, position, or offset) of an entire event hub. Consumer groups enable multiple consuming applications to each have a separate view of the event stream, and to read the stream independently at their own pace and with their own offsets.
Default value: `$Default`

`connection_string` :
_string_
The connection string required to communicate with Event Hubs, steps here https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-get-connection-string.

A Blob Storage account is required in order to store/retrieve/update the offset or state of the eventhub messages. This means that after stopping the filebeat azure module it can start back up at the spot that it stopped processing messages.

`storage_account` :
_string_
The name of the storage account the state/offsets will be stored and updated.

`storage_account_key` :
_string_
The storage account key, this key will be used to authorize access to data in your storage account.

`resource_manager_endpoint` :
_string_
Optional, by default we are using the azure public environment, to override, users can provide a specific resource manager endpoint in order to use a different azure environment.

Resource manager endpoints:

```text
# Azure ChinaCloud
https://management.chinacloudapi.cn/

# Azure GermanCloud
https://management.microsoftazure.de/

# Azure PublicCloud 
https://management.azure.com/

# Azure USGovernmentCloud
https://management.usgovcloudapi.net/
```

## Logs

### eventhub

The `eventhub` data stream of the Azure Logs package will collect any events that have been streamed through an azure event hub.

An example event for `eventhub` looks as following:

```json
{
    "agent": {
        "hostname": "docker-fleet-agent",
        "name": "docker-fleet-agent",
        "id": "b659ebed-5338-45f3-9762-1bcf2c1ad0e1",
        "type": "filebeat",
        "ephemeral_id": "42a183d5-df19-4008-8776-d9765bc01d50",
        "version": "7.15.0"
    },
    "elastic_agent": {
        "id": "b659ebed-5338-45f3-9762-1bcf2c1ad0e1",
        "version": "7.15.0",
        "snapshot": true
    },
    "message": "{\\\"ReleaseVersion\\\":\\\"6.2021.39.11+d1f0e29.release_2021w39_az\\\",\\\"RoleLocation\\\":\\\"North Europe\\\",\\\"callerIpAddress\\\":\\\"77.170.179.229\\\",\\\"category\\\":\\\"Administrative\\\",\\\"correlationId\\\":\\\"a75a0752-ebbb-42bf-831f-43788a8c1193\\\",\\\"durationMs\\\":\\\"0\\\",\\\"identity\\\":{\\\"authorization\\\":{\\\"action\\\":\\\"Microsoft.ServiceBus\\/namespaces\\/delete\\\",\\\"evidence\\\":{\\\"principalId\\\":\\\"68b1adf93eb744b08eb8ce96522a08d3\\\",\\\"principalType\\\":\\\"User\\\",\\\"role\\\":\\\"Owner\\\",\\\"roleAssignmentId\\\":\\\"7f06f09dd6764b44930adbec3f10e92b\\\",\\\"roleAssignmentScope\\\":\\\"\\/providers\\/Microsoft.Management\\/managementGroups\\/5341238b-665c-4eb4-b259-b250371ae430\\\",\\\"roleDefinitionId\\\":\\\"8e3af657a8ff443ca75c2fe8c4bcb635\\\"},\\\"scope\\\":\\\"\\/subscriptions\\/7657426d-c4c3-44ac-88a2-3b2cd59e6dba\\/resourcegroups\\/obs-test\\/providers\\/Microsoft.ServiceBus\\/namespaces\\/testobs\\\"},\\\"claims\\\":{\\\"aio\\\":\\\"ATQAy\\/8TAAAAgFUjNWoJWKgHlAK2AL92UMeUsb6VD5zck\\/myDZPucX5V3Gc8SDMg5vTV28NUy5N7\\\",\\\"appid\\\":\\\"c44b4083-3bb0-49c1-b47d-974e53cbdf3c\\\",\\\"appidacr\\\":\\\"2\\\",\\\"aud\\\":\\\"https:\\/\\/management.core.windows.net\\/\\\",\\\"exp\\\":\\\"1634290798\\\",\\\"groups\\\":\\\"644c6686-9ef1-4b69-9410-107664a9e1f0,9ed1993c-ce9c-4915-a04d-58c6f5f7ee12,a953f548-26ab-47b2-be7d-65586b7bcc2a\\\",\\\"http:\\/\\/schemas.microsoft.com\\/2012\\/01\\/devicecontext\\/claims\\/identifier\\\":\\\"1060004c-63dc-465b-b868-ec6547176c58\\\",\\\"http:\\/\\/schemas.microsoft.com\\/claims\\/authnclassreference\\\":\\\"1\\\",\\\"http:\\/\\/schemas.microsoft.com\\/claims\\/authnmethodsreferences\\\":\\\"pwd,rsa\\\",\\\"http:\\/\\/schemas.microsoft.com\\/identity\\/claims\\/objectidentifier\\\":\\\"68b1adf9-3eb7-44b0-8eb8-ce96522a08d3\\\",\\\"http:\\/\\/schemas.microsoft.com\\/identity\\/claims\\/scope\\\":\\\"user_impersonation\\\",\\\"http:\\/\\/schemas.microsoft.com\\/identity\\/claims\\/tenantid\\\":\\\"4fa94b7d-a743-486f-abcc-6c276c44cf4b\\\",\\\"http:\\/\\/schemas.xmlsoap.org\\/ws\\/2005\\/05\\/identity\\/claims\\/givenname\\\":\\\"Mariana\\\",\\\"http:\\/\\/schemas.xmlsoap.org\\/ws\\/2005\\/05\\/identity\\/claims\\/name\\\":\\\"mariana@elastic.co\\\",\\\"http:\\/\\/schemas.xmlsoap.org\\/ws\\/2005\\/05\\/identity\\/claims\\/nameidentifier\\\":\\\"a9L2WR3XZN5ANzAqwLx_4aamU49JG6kqaE5JZkXdeNs\\\",\\\"http:\\/\\/schemas.xmlsoap.org\\/ws\\/2005\\/05\\/identity\\/claims\\/surname\\\":\\\"Dima\\\",\\\"http:\\/\\/schemas.xmlsoap.org\\/ws\\/2005\\/05\\/identity\\/claims\\/upn\\\":\\\"mariana@elastic.co\\\",\\\"iat\\\":\\\"1634286898\\\",\\\"ipaddr\\\":\\\"77.170.179.229\\\",\\\"iss\\\":\\\"https:\\/\\/sts.windows.net\\/4fa94b7d-a743-486f-abcc-6c276c44cf4b\\/\\\",\\\"name\\\":\\\"Mariana Dima\\\",\\\"nbf\\\":\\\"1634286898\\\",\\\"puid\\\":\\\"1003200045B17AD4\\\",\\\"rh\\\":\\\"0.AVEAfUupT0Onb0irzGwnbETPS4NAS8SwO8FJtH2XTlPL3zxRAA8.\\\",\\\"uti\\\":\\\"yUcYeZwj9EWeA-rTCtRwAA\\\",\\\"ver\\\":\\\"1.0\\\",\\\"wids\\\":\\\"5d6b6bb7-de71-4623-b4af-96380a352509\\\",\\\"xms_tcdt\\\":\\\"1469565974\\\"}},\\\"level\\\":\\\"Information\\\",\\\"operationName\\\":\\\"MICROSOFT.SERVICEBUS\\/NAMESPACES\\/DELETE\\\",\\\"properties\\\":{\\\"entity\\\":\\\"\\/subscriptions\\/7657426d-c4c3-44ac-88a2-3b2cd59e6dba\\/resourcegroups\\/obs-test\\/providers\\/Microsoft.ServiceBus\\/namespaces\\/testobs\\\",\\\"eventCategory\\\":\\\"Administrative\\\",\\\"hierarchy\\\":\\\"4fa94b7d-a743-486f-abcc-6c276c44cf4b\\/5341238b-665c-4eb4-b259-b250371ae430\\/7657426d-c4c3-44ac-88a2-3b2cd59e6dba\\\",\\\"message\\\":\\\"Microsoft.ServiceBus\\/namespaces\\/delete\\\"},\\\"resourceId\\\":\\\"\\/SUBSCRIPTIONS\\/7657426D-C4C3-44AC-88A2-3B2CD59E6DBA\\/RESOURCEGROUPS\\/OBS-TEST\\/PROVIDERS\\/MICROSOFT.SERVICEBUS\\/NAMESPACES\\/TESTOBS\\\",\\\"resultSignature\\\":\\\"Started.\\\",\\\"resultType\\\":\\\"Start\\\",\\\"tenantId\\\":\\\"4fa94b7d-a743-486f-abcc-6c276c44cf4b\\\",\\\"time\\\":\\\"2021-10-15T09:08:29.9268177Z\\\"}\\r\\n",
    "azure-eventhub": {
        "sequence_number": 1215,
        "consumer_group": "$Default",
        "offset": 274878093752,
        "eventhub": "insights-activity-logs",
        "enqueued_time": "2021-10-15T09:14:25.419Z"
    },
    "tags": [
        "azure-eventhub"
    ],
    "input": {
        "type": "azure-eventhub"
    },
    "@timestamp": "2021-10-18T12:31:17.027Z",
    "ecs": {
        "version": "1.12.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "azure.eventhub"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "4.19.128-microsoft-standard",
            "codename": "Core",
            "name": "CentOS Linux",
            "family": "redhat",
            "type": "linux",
            "version": "7 (Core)",
            "platform": "centos"
        },
        "containerized": true,
        "ip": [
            "172.27.0.7"
        ],
        "name": "docker-fleet-agent",
        "id": "6505f7ca36739e7eb909bdb52bf3ec18",
        "mac": [
            "02:42:ac:1b:00:07"
        ],
        "architecture": "x86_64"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2021-10-18T12:31:17Z",
        "kind": "event",
        "dataset": "azure.eventhub"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure-eventhub.consumer_group | consumer group | keyword |
| azure-eventhub.enqueued_time | The enqueued time. | keyword |
| azure-eventhub.eventhub | Event hub name. | keyword |
| azure-eventhub.offset | Offset | long |
| azure-eventhub.partition_id | Partition ID | keyword |
| azure-eventhub.sequence_number | Sequence number | long |
| azure.correlation_id | Correlation ID | keyword |
| azure.resource.authorization_rule | Authorization rule | keyword |
| azure.resource.group | Resource group | keyword |
| azure.resource.id | Resource ID | keyword |
| azure.resource.name | Name | keyword |
| azure.resource.namespace | Resource type/namespace | keyword |
| azure.resource.provider | Resource type/namespace | keyword |
| azure.subscription_id | Azure subscription ID | keyword |
| azure.tenant_id | tenant ID | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | The cloud project identifier. Examples: Google Cloud Project id, Azure Project id. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host, resource, or service is located. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
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
| destination.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.mime_type | MIME type should identify the format of the file or stream of bytes using https://www.iana.org/assignments/media-types/media-types.xhtml[IANA official types], where possible. When more than one type is applicable, the most specific type should be used. | keyword |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| geo.city_name | City name. | keyword |
| geo.continent_name | Name of the continent. | keyword |
| geo.country_iso_code | Country ISO code. | keyword |
| geo.country_name | Country name. | keyword |
| geo.location | Longitude and latitude. | geo_point |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.full_name.text | Multi-field of `user.full_name`. | match_only_text |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |

