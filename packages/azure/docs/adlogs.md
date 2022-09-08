# Active Directory Logs

The Azure Logs integration retrieves different types of log data from Azure.

There are several requirements before using the integration since the logs will actually be read from azure event hubs.

- The logs have to be [exported first to the event hub](https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-create-kafka-enabled).
- To export activity logs to event hubs users can follow the steps [here](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-export).
- To export audit and sign-in logs to event hubs users can follow the steps [here](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/tutorial-azure-monitor-stream-logs-to-event-hub).

Azure Active Directory Logs contain:

Sign-in logs – Information about sign-ins and how your resources are used by your users.

Audit logs – Information about changes applied to your tenant such as users and group management or updates applied to your tenant’s resources.

## Settings

`eventhub` :
  _string_
It is a fully managed, real-time data ingestion service. Elastic recommends using only letters, numbers, and the hyphen (-) character for Event Hub names to maximize compatibility. You can use existing Event Hubs having underscores (_) in the Event Hub name; in this case, the integration will replace underscores with hyphens (-) when it uses the Event Hub name to create dependent Azure resources behind the scenes (e.g., the storage account container to store Event Hub consumer offsets). Elastic also recommends using a separate event hub for each log type as the field mappings of each log type differ.
Default value `insights-operational-logs`.

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

### auditlogs

The `auditlogs` dataset of the Azure Logs package will collect any audit events that have been streamed through an azure event hub.

An example event for `auditlogs` looks as following:

```json
{
    "log": {
        "level": "Information"
    },
    "cloud": {
        "provider": "azure"
    },
    "@timestamp": "2020-11-02T08:51:36.997Z",
    "ecs": {
        "version": "1.5.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "azure.auditlogs"
    },
    "event": {
        "duration": 0,
        "ingested": "2020-10-30T20:47:48.123859400Z",
        "kind": "event",
        "action": "MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE",
        "dataset": "azure.auditlogs",
        "outcome": "success"
    },
    "azure.correlation_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
    "azure.resource.id": "/tenants/8a4de8b5-095c-47d0-a96f-a75130c61d53/providers/Microsoft.aadiam",
    "azure.resource.provider": "Microsoft.aadiam",
    "azure.tenant_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
    "azure.auditlogs.category": "AuditLogs",
    "azure.auditlogs.identity": "Device Registration Service",
    "azure.auditlogs.operation_name": "Update device",
    "azure.auditlogs.operation_version": "1.0",
    "azure.auditlogs.properties.activity_datetime": "2019-10-18T15:30:51.0273716+00:00",
    "azure.auditlogs.properties.activity_display_name": "Update device",
    "azure.auditlogs.properties.category": "Device",
    "azure.auditlogs.properties.correlation_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
    "azure.auditlogs.properties.id": "Directory_ESQ",
    "azure.auditlogs.properties.initiated_by.app.displayName": "Device Registration Service",
    "azure.auditlogs.properties.initiated_by.app.servicePrincipalId": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
    "azure.auditlogs.properties.logged_by_service": "Core Directory",
    "azure.auditlogs.properties.operation_type": "Update",
    "azure.auditlogs.properties.result_reason": "",
    "azure.auditlogs.properties.target_resources.0.display_name": "LAPTOP-12",
    "azure.auditlogs.properties.target_resources.0.id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
    "azure.auditlogs.properties.target_resources.0.modified_properties.0.new_value": "\"\"",
    "azure.auditlogs.properties.target_resources.0.type": "Device",
    "azure.auditlogs.result_signature": "None"
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.auditlogs.category | The category of the operation.  Currently, Audit is the only supported value. | keyword |
| azure.auditlogs.identity | Identity | keyword |
| azure.auditlogs.level | Value for level. | float |
| azure.auditlogs.operation_name | The operation name | keyword |
| azure.auditlogs.operation_version | The operation version | keyword |
| azure.auditlogs.properties.activity_datetime | Activity timestamp | date |
| azure.auditlogs.properties.activity_display_name | Activity display name | keyword |
| azure.auditlogs.properties.authentication_protocol | Authentication protocol type. | keyword |
| azure.auditlogs.properties.category | category | keyword |
| azure.auditlogs.properties.correlation_id | Correlation ID | keyword |
| azure.auditlogs.properties.id | ID | keyword |
| azure.auditlogs.properties.initiated_by.app.appId | App ID | keyword |
| azure.auditlogs.properties.initiated_by.app.displayName | Display name | keyword |
| azure.auditlogs.properties.initiated_by.app.servicePrincipalId | Service principal ID | keyword |
| azure.auditlogs.properties.initiated_by.app.servicePrincipalName | Service principal name | keyword |
| azure.auditlogs.properties.initiated_by.user.displayName | Display name | keyword |
| azure.auditlogs.properties.initiated_by.user.id | ID | keyword |
| azure.auditlogs.properties.initiated_by.user.ipAddress | ip Address | keyword |
| azure.auditlogs.properties.initiated_by.user.userPrincipalName | User principal name | keyword |
| azure.auditlogs.properties.logged_by_service | Logged by service | keyword |
| azure.auditlogs.properties.operation_type | Operation type | keyword |
| azure.auditlogs.properties.result | Log result | keyword |
| azure.auditlogs.properties.result_reason | Reason for the log result | keyword |
| azure.auditlogs.properties.target_resources.\*.display_name | Display name | keyword |
| azure.auditlogs.properties.target_resources.\*.id | ID | keyword |
| azure.auditlogs.properties.target_resources.\*.ip_address | ip Address | keyword |
| azure.auditlogs.properties.target_resources.\*.modified_properties.\*.display_name | Display value | keyword |
| azure.auditlogs.properties.target_resources.\*.modified_properties.\*.new_value | New value | keyword |
| azure.auditlogs.properties.target_resources.\*.modified_properties.\*.old_value | Old value | keyword |
| azure.auditlogs.properties.target_resources.\*.type | Type | keyword |
| azure.auditlogs.properties.target_resources.\*.user_principal_name | User principal name | keyword |
| azure.auditlogs.result_signature | Result signature | keyword |
| azure.auditlogs.tenant_id | Tenant ID | keyword |
| azure.correlation_id | Correlation ID | keyword |
| azure.resource.authorization_rule | Authorization rule | keyword |
| azure.resource.group | Resource group | keyword |
| azure.resource.id | Resource ID | keyword |
| azure.resource.name | Name | keyword |
| azure.resource.namespace | Resource type/namespace | keyword |
| azure.resource.provider | Resource type/namespace | keyword |
| azure.subscription_id | Azure subscription ID | keyword |
| azure.tenant_id | tenant ID | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
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
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.full_name.text | Multi-field of `user.full_name`. | match_only_text |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |


### signinlogs

The `signinlogs` dataset of the Azure Logs package will collect any sign-in events that have been streamed through an Azure Event Hub.

An example event for `signinlogs` looks as following:

```json
{
    "log": {
        "level": "4"
    },
    "source": {
        "geo": {
            "continent_name": "Oceania",
            "country_name": "Australia",
            "location": {
                "lon": 143.2104,
                "lat": -33.494
            },
            "country_iso_code": "AU"
        },
        "as": {
            "number": 13335,
            "organization": {
                "name": "Cloudflare, Inc."
            }
        },
        "address": "1.1.1.1",
        "ip": "1.1.1.1"
    },
    "message": "This error occurred due to 'Keep me signed in' interrupt when the user was signing-in.",
    "tags": [
        "preserve_original_event"
    ],
    "geo": {
        "country_name": "Seine-Et-Marne",
        "city_name": "Champs-Sur-Marne",
        "location": {
            "lon": 2.12341234,
            "lat": 48.12341234
        },
        "country_iso_code": "FR"
    },
    "cloud": {
        "provider": "azure"
    },
    "@timestamp": "2019-10-18T09:45:48.072Z",
    "ecs": {
        "version": "1.11.0"
    },
    "related": {
        "ip": [
            "1.1.1.1"
        ]
    },
    "client": {
        "ip": "1.1.1.1"
    },
    "event": {
        "duration": 0,
        "ingested": "2021-09-14T17:20:47.736433526Z",
        "original": "{\"Level\":\"4\",\"callerIpAddress\":\"1.1.1.1\",\"category\":\"SignInLogs\",\"correlationId\":\"8a4de8b5-095c-47d0-a96f-a75130c61d53\",\"durationMs\":0,\"identity\":\"Test LTest\",\"location\":\"FR\",\"operationName\":\"Sign-in activity\",\"operationVersion\":\"1.0\",\"properties\":{\"appDisplayName\":\"Office 365\",\"appId\":\"8a4de8b5-095c-47d0-a96f-a75130c61d53\",\"clientAppUsed\":\"Browser\",\"conditionalAccessStatus\":\"notApplied\",\"correlationId\":\"8a4de8b5-095c-47d0-a96f-a75130c61d53\",\"createdDateTime\":\"2019-10-18T04:45:48.0729893-05:00\",\"deviceDetail\":{\"browser\":\"Chrome 77.0.3865\",\"deviceId\":\"\",\"operatingSystem\":\"MacOs\"},\"id\":\"8a4de8b5-095c-47d0-a96f-a75130c61d53\",\"ipAddress\":\"1.1.1.1\",\"isInteractive\":false,\"location\":{\"city\":\"Champs-Sur-Marne\",\"countryOrRegion\":\"FR\",\"geoCoordinates\":{\"latitude\":48.12341234,\"longitude\":2.12341234},\"state\":\"Seine-Et-Marne\"},\"originalRequestId\":\"8a4de8b5-095c-47d0-a96f-a75130c61d53\",\"processingTimeInMilliseconds\":239,\"riskDetail\":\"none\",\"riskLevelAggregated\":\"none\",\"riskLevelDuringSignIn\":\"none\",\"riskState\":\"none\",\"servicePrincipalId\":\"\",\"status\":{\"errorCode\":50140,\"failureReason\":\"This error occurred due to 'Keep me signed in' interrupt when the user was signing-in.\"},\"tokenIssuerName\":\"\",\"tokenIssuerType\":\"AzureAD\",\"userDisplayName\":\"Test LTest\",\"userId\":\"8a4de8b5-095c-47d0-a96f-a75130c61d53\",\"userPrincipalName\":\"test@elastic.co\"},\"resourceId\":\"/tenants/8a4de8b5-095c-47d0-a96f-a75130c61d53/providers/Microsoft.aadiam\",\"resultDescription\":\"This error occurred due to 'Keep me signed in' interrupt when the user was signing-in.\",\"resultSignature\":\"None\",\"resultType\":\"50140\",\"tenantId\":\"8a4de8b5-095c-47d0-a96f-a75130c61d53\",\"time\":\"2019-10-18T09:45:48.0729893Z\"}",
        "kind": "event",
        "action": "Sign-in activity",
        "id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
        "category": [
            "authentication"
        ],
        "type": [
            "info"
        ],
        "outcome": "failure"
    },
    "user": {
        "name": "test",
        "full_name": "Test LTest",
        "id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
        "domain": "elastic.co"
    },
    "azure": {
        "tenant_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
        "correlation_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
        "signinlogs": {
            "operation_name": "Sign-in activity",
            "result_description": "This error occurred due to 'Keep me signed in' interrupt when the user was signing-in.",
            "result_type": "50140",
            "operation_version": "1.0",
            "identity": "Test LTest",
            "result_signature": "None",
            "category": "SignInLogs",
            "properties": {
                "risk_level_aggregated": "none",
                "client_app_used": "Browser",
                "is_interactive": false,
                "service_principal_id": "",
                "app_display_name": "Office 365",
                "created_at": "2019-10-18T04:45:48.0729893-05:00",
                "risk_level_during_signin": "none",
                "device_detail": {
                    "device_id": "",
                    "operating_system": "MacOs",
                    "browser": "Chrome 77.0.3865"
                },
                "risk_detail": "none",
                "token_issuer_name": "",
                "risk_state": "none",
                "user_principal_name": "test@elastic.co",
                "token_issuer_type": "AzureAD",
                "processing_time_ms": 239,
                "original_request_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
                "user_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
                "conditional_access_status": "notApplied",
                "correlation_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
                "id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
                "user_display_name": "Test LTest",
                "app_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
                "status": {
                    "error_code": 50140
                }
            }
        },
        "resource": {
            "provider": "Microsoft.aadiam",
            "id": "/tenants/8a4de8b5-095c-47d0-a96f-a75130c61d53/providers/Microsoft.aadiam"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.correlation_id | Correlation ID | keyword |
| azure.resource.authorization_rule | Authorization rule | keyword |
| azure.resource.group | Resource group | keyword |
| azure.resource.id | Resource ID | keyword |
| azure.resource.name | Name | keyword |
| azure.resource.namespace | Resource type/namespace | keyword |
| azure.resource.provider | Resource type/namespace | keyword |
| azure.signinlogs.category | Category | keyword |
| azure.signinlogs.identity | Identity | keyword |
| azure.signinlogs.operation_name | The operation name | keyword |
| azure.signinlogs.operation_version | The operation version | keyword |
| azure.signinlogs.properties.app_display_name | App display name | keyword |
| azure.signinlogs.properties.app_id | App ID | keyword |
| azure.signinlogs.properties.applied_conditional_access_policies | A list of conditional access policies that are triggered by the corresponding sign-in activity. | array |
| azure.signinlogs.properties.authentication_details | The result of the authentication attempt and additional details on the authentication method. | array |
| azure.signinlogs.properties.authentication_processing_details | Additional authentication processing details, such as the agent name in case of PTA/PHS or Server/farm name in case of federated authentication. | flattened |
| azure.signinlogs.properties.authentication_protocol | Authentication protocol type. | keyword |
| azure.signinlogs.properties.authentication_requirement | This holds the highest level of authentication needed through all the sign-in steps, for sign-in to succeed. | keyword |
| azure.signinlogs.properties.authentication_requirement_policies | Set of CA policies that apply to this sign-in, each as CA: policy name, and/or MFA: Per-user | flattened |
| azure.signinlogs.properties.autonomous_system_number | Autonomous system number. | long |
| azure.signinlogs.properties.client_app_used | Client app used | keyword |
| azure.signinlogs.properties.conditional_access_status | Conditional access status | keyword |
| azure.signinlogs.properties.correlation_id | Correlation ID | keyword |
| azure.signinlogs.properties.created_at | Date and time (UTC) the sign-in was initiated. | date |
| azure.signinlogs.properties.cross_tenant_access_type |  | keyword |
| azure.signinlogs.properties.device_detail.browser | Browser | keyword |
| azure.signinlogs.properties.device_detail.device_id | Device ID | keyword |
| azure.signinlogs.properties.device_detail.display_name | Display name | keyword |
| azure.signinlogs.properties.device_detail.is_compliant | If the device is compliant | boolean |
| azure.signinlogs.properties.device_detail.is_managed | If the device is managed | boolean |
| azure.signinlogs.properties.device_detail.operating_system | Operating system | keyword |
| azure.signinlogs.properties.device_detail.trust_type | Trust type | keyword |
| azure.signinlogs.properties.flagged_for_review |  | boolean |
| azure.signinlogs.properties.home_tenant_id |  | keyword |
| azure.signinlogs.properties.id | Unique ID representing the sign-in activity. | keyword |
| azure.signinlogs.properties.incoming_token_type | Incoming token type. | keyword |
| azure.signinlogs.properties.is_interactive | Is interactive | boolean |
| azure.signinlogs.properties.is_tenant_restricted |  | boolean |
| azure.signinlogs.properties.network_location_details | The network location details including the type of network used and its names. | array |
| azure.signinlogs.properties.original_request_id | Original request ID | keyword |
| azure.signinlogs.properties.processing_time_ms | Processing time in milliseconds | float |
| azure.signinlogs.properties.resource_display_name | Resource display name | keyword |
| azure.signinlogs.properties.resource_id | The identifier of the resource that the user signed in to. | keyword |
| azure.signinlogs.properties.resource_tenant_id |  | keyword |
| azure.signinlogs.properties.risk_detail | Risk detail | keyword |
| azure.signinlogs.properties.risk_event_types | The list of risk event types associated with the sign-in. Possible values: unlikelyTravel, anonymizedIPAddress, maliciousIPAddress, unfamiliarFeatures, malwareInfectedIPAddress, suspiciousIPAddress, leakedCredentials, investigationsThreatIntelligence, generic, or unknownFutureValue. | keyword |
| azure.signinlogs.properties.risk_event_types_v2 | The list of risk event types associated with the sign-in. Possible values: unlikelyTravel, anonymizedIPAddress, maliciousIPAddress, unfamiliarFeatures, malwareInfectedIPAddress, suspiciousIPAddress, leakedCredentials, investigationsThreatIntelligence, generic, or unknownFutureValue. | keyword |
| azure.signinlogs.properties.risk_level_aggregated | Risk level aggregated | keyword |
| azure.signinlogs.properties.risk_level_during_signin | Risk level during signIn | keyword |
| azure.signinlogs.properties.risk_state | Risk state | keyword |
| azure.signinlogs.properties.service_principal_credential_key_id | Key id of the service principal that initiated the sign-in. | keyword |
| azure.signinlogs.properties.service_principal_id | The application identifier used for sign-in. This field is populated when you are signing in using an application. | keyword |
| azure.signinlogs.properties.service_principal_name | The application name used for sign-in. This field is populated when you are signing in using an application. | keyword |
| azure.signinlogs.properties.sso_extension_version |  | keyword |
| azure.signinlogs.properties.status.error_code | Error code | long |
| azure.signinlogs.properties.token_issuer_name | Token issuer name | keyword |
| azure.signinlogs.properties.token_issuer_type | Token issuer type | keyword |
| azure.signinlogs.properties.unique_token_identifier | Unique token identifier for the request. | keyword |
| azure.signinlogs.properties.user_display_name | User display name | keyword |
| azure.signinlogs.properties.user_id | User ID | keyword |
| azure.signinlogs.properties.user_principal_name | User principal name | keyword |
| azure.signinlogs.properties.user_type |  | keyword |
| azure.signinlogs.result_description | Result description | keyword |
| azure.signinlogs.result_signature | Result signature | keyword |
| azure.signinlogs.result_type | Result type | keyword |
| azure.signinlogs.tenant_id | Tenant ID | keyword |
| azure.subscription_id | Azure subscription ID | keyword |
| azure.tenant_id | tenant ID | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
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
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |

