# Microsoft Graph Activity Logs

Microsoft Graph Activity Logs provide an audit trail of all HTTP requests that the Microsoft Graph service has received and processed for a tenant. Microsoft Graph Activity Logs gives full visibility into all transactions made by applications and other API clients that you have consented to in the tenant. Refer to [Microsoft Graph Activity Common Usecases](https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview#common-use-cases-for-microsoft-graph-activity-logs) for more use cases.

Tenant administrators can configure the collection and storage destinations of Microsoft Graph Activity Logs through Diagnostic Setting in the Entra Portal. This integration uses Azure Event Hubs destination to stream Microsoft Graph Activity Logs to Elastic.

## Requirements and Setup

### Prerequisites

Following privileges are required to collect Microsoft Graph Activity Logs:
- A Microsoft Entra ID P1 or P2 tenant license in your tenant.
- A `Security Administrator` or `Global Administrator` Microsoft Entra ID role to configure the diagnostic settings.
Refer to [Microsoft Graph Prerequisites](https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview#prerequisites) for more information on required privileges.

### Setup

Refer to the [Azure Logs](https://docs.elastic.co/integrations/azure) page for more information about setting up and using this integration.

### Limitations

- Activities of multi-tenant applications belonging to another tenant are not available.
- In few rare cases, events might take up to 2 hours to be delivered to Event Hubs.
Refer to [Microsoft Graph Activity Limitations](https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview#limitations) for more information.

## Settings

`eventhub` :
  _string_
It is a fully managed, real-time data ingestion service. Elastic recommends using only letters, numbers, and the hyphen (-) character for Event Hub names to maximize compatibility. You _can_ use existing Event Hubs having underscores (_) in the Event Hub name; in this case, the integration will replace underscores with hyphens (-) when it uses the Event Hub name to create dependent Azure resources behind the scenes (e.g., the storage account container to store Event Hub consumer offsets). Elastic also recommends using a separate event hub for each log type as the field mappings of each log type differ.
Default value `insights-operational-logs`.

`consumer_group` :
_string_
 The publish/subscribe mechanism of Event Hubs is enabled through consumer groups. A consumer group is a view (state, position, or offset) of an entire event hub. Consumer groups enable multiple consuming applications to each have a separate view of the event stream, and to read the stream independently at their own pace and with their own offsets.
Default value: `$Default`

`connection_string` :
_string_
The connection string required to communicate with Event Hubs, steps [here](https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-get-connection-string).

A Blob Storage account is required in order to store/retrieve/update the offset or state of the eventhub messages. This means that after stopping the filebeat azure module it can start back up at the spot that it stopped processing messages.

`storage_account` :
_string_
The name of the storage account the state/offsets will be stored and updated.

`storage_account_key` :
_string_
The storage account key, this key will be used to authorize access to data in your storage account.

`storage_account_container` :
_string_
The storage account container where the integration stores the checkpoint data for the consumer group. It is an advanced option to use with extreme care. You MUST use a dedicated storage account container for each Azure log type (activity, sign-in, audit logs, and others). DO NOT REUSE the same container name for more than one Azure log type. See [Container Names](https://docs.microsoft.com/en-us/rest/api/storageservices/naming-and-referencing-containers--blobs--and-metadata#container-names) for details on naming rules from Microsoft. The integration generates a default container name if not specified. 

`resource_manager_endpoint` :
_string_
Optional, by default we are using the azure public environment, to override, users can provide a specific resource manager endpoint in order to use a different Azure environment.

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

### graphactivitylogs

The `graphactivitylogs` data stream of the Azure Logs package will collect Microsoft Graph activity events that have been streamed through an azure event hub.

An example event for `graphactivitylogs` looks as following:

```json
{
    "@timestamp": "2024-03-07T10:24:44.793Z",
    "azure": {
        "correlation_id": "f7839da0-e7d1-4e4f-985a-64937fbge347",
        "graphactivitylogs": {
            "category": "MicrosoftGraphActivityLogs",
            "operation_name": "Microsoft Graph Activity",
            "operation_version": "v1.0",
            "properties": {
                "api_version": "v1.0",
                "app_id": "a5a68e32-269a-3c91-a5e2-b9254e67hb29",
                "client_auth_method": 2,
                "client_request_id": "2fe58790-a848-4a93-9d2c-5645972aejk9",
                "identity_provider": "https://sts.windows.net/ab30785b-417f-42a4-b5dc-8f9051718acb/",
                "operation_id": "f7839da0-e7d1-4e4f-985a-64937fbge347",
                "roles": [
                    "Application.Read.All",
                    "Domain.Read.All",
                    "GroupMember.Read.All",
                    "LicenseAssignment.ReadWrite.All",
                    "Organization.Read.All",
                    "Policy.Read.ConditionalAccess",
                    "RoleManagement.Read.Directory",
                    "Team.ReadBasic.All",
                    "TeamsTab.Create",
                    "TeamsTab.Read.All",
                    "TeamsTab.ReadWrite.All",
                    "User.Read.All"
                ],
                "service_principal_id": "f2aq4c71-31e3-5065-91g3-4b2dfbsv50fg",
                "sign_in_activity_id": "sign-in_ActivityId",
                "time_generated": "2024-03-07T10:24:44.793Z",
                "token_issued_at": "2024-03-07T10:19:44.000Z",
                "wids": [
                    "a207b4d3-0g8d-90cb-bhj5-d80n3121e69"
                ]
            },
            "result_signature": "200"
        },
        "resource": {
            "id": "/TENANTS/AB30785B-417F-42A4-B5DC-8F9051718ACB/PROVIDERS/MICROSOFT.AADIAM",
            "provider": "MICROSOFT.AADIAM"
        },
        "tenant_id": "ab30785b-417f-42a4-b5dc-8f9051718acb"
    },
    "client": {
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
        "ip": "81.2.69.143"
    },
    "cloud": {
        "account": {
            "id": "ab30785b-417f-42a4-b5dc-8f9051718acb"
        },
        "provider": "azure",
        "region": "France Central",
        "service": {
            "name": "Microsoft Graph"
        }
    },
    "destination": {
        "geo": {
            "region_name": "France Central"
        }
    },
    "ecs": {
        "version": "8.0.0"
    },
    "event": {
        "action": "Microsoft Graph Activity",
        "duration": 1213372224,
        "kind": "event",
        "original": "{\"Level\":4,\"callerIpAddress\":\"81.2.69.143\",\"category\":\"MicrosoftGraphActivityLogs\",\"correlationId\":\"f7839da0-e7d1-4e4f-985a-64937fbge347\",\"durationMs\":1100725,\"location\":\"France Central\",\"operationName\":\"Microsoft Graph Activity\",\"operationVersion\":\"v1.0\",\"properties\":{\"apiVersion\":\"v1.0\",\"appId\":\"a5a68e32-269a-3c91-a5e2-b9254e67hb29\",\"atContent\":\"\",\"clientAuthMethod\":\"2\",\"clientRequestId\":\"2fe58790-a848-4a93-9d2c-5645972aejk9\",\"durationMs\":1100725,\"identityProvider\":\"https://sts.windows.net/ab30785b-417f-42a4-b5dc-8f9051718acb/\",\"ipAddress\":\"81.2.69.143\",\"location\":\"France Central\",\"operationId\":\"f7839da0-e7d1-4e4f-985a-64937fbge347\",\"requestId\":\"f7839da0-e7d1-4e4f-985a-64937fbge347\",\"requestMethod\":\"GET\",\"requestUri\":\"https://graph.microsoft.com/v1.0/directoryRoles\",\"responseSizeBytes\":4300,\"responseStatusCode\":200,\"roles\":\"Application.Read.All Domain.Read.All GroupMember.Read.All LicenseAssignment.ReadWrite.All Organization.Read.All Policy.Read.ConditionalAccess RoleManagement.Read.Directory Team.ReadBasic.All TeamsTab.Create TeamsTab.Read.All TeamsTab.ReadWrite.All User.Read.All\",\"scopes\":null,\"servicePrincipalId\":\"f2aq4c71-31e3-5065-91g3-4b2dfbsv50fg\",\"signInActivityId\":\"sign-in_ActivityId\",\"tenantId\":\"ab30785b-417f-42a4-b5dc-8f9051718acb\",\"timeGenerated\":\"2024-03-07T10:24:44.7939418Z\",\"tokenIssuedAt\":\"2024-03-07T10:19:44Z\",\"userAgent\":\"\",\"userId\":null,\"wids\":\"a207b4d3-0g8d-90cb-bhj5-d80n3121e69\"},\"resourceId\":\"/TENANTS/AB30785B-417F-42A4-B5DC-8F9051718ACB/PROVIDERS/MICROSOFT.AADIAM\",\"resultSignature\":\"200\",\"tenantId\":\"ab30785b-417f-42a4-b5dc-8f9051718acb\",\"time\":\"2024-03-07T10:24:44.7939418Z\"}",
        "type": [
            "access"
        ]
    },
    "http": {
        "request": {
            "id": "f7839da0-e7d1-4e4f-985a-64937fbge347",
            "method": "GET"
        },
        "response": {
            "bytes": 4300,
            "status_code": 200
        }
    },
    "log": {
        "level": "4"
    },
    "related": {
        "ip": [
            "81.2.69.143"
        ]
    },
    "source": {
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
        "ip": "81.2.69.143"
    },
    "tags": [
        "preserve_original_event"
    ],
    "url": {
        "domain": "graph.microsoft.com",
        "extension": "0/directoryRoles",
        "original": "https://graph.microsoft.com/v1.0/directoryRoles",
        "path": "/v1.0/directoryRoles",
        "scheme": "https"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.correlation_id | Correlation ID. | keyword |
| azure.graphactivitylogs.category | Azure Event Category. For example, Graph Activity Logs has value `MicrosoftGraphActivityLogs`. | keyword |
| azure.graphactivitylogs.operation_name | Operation name. | keyword |
| azure.graphactivitylogs.operation_version | The Graph API version of the event. | keyword |
| azure.graphactivitylogs.properties.api_version | The API version of the event. | keyword |
| azure.graphactivitylogs.properties.app_id | The identifier for the application. | keyword |
| azure.graphactivitylogs.properties.at_content | Reserved for future use. | keyword |
| azure.graphactivitylogs.properties.billed_size | The record size in bytes. | double |
| azure.graphactivitylogs.properties.client_auth_method | Indicates how the client was authenticated. For a public client, the value is 0. If client ID and client secret are used, the value is 1. If a client certificate was used for authentication, the value is 2. | integer |
| azure.graphactivitylogs.properties.client_request_id | The client request identifier when sent. If no client request identifier is sent, the value will be equal to the operation identifier. | keyword |
| azure.graphactivitylogs.properties.identity_provider | The identity provider that authenticated the subject of the token. | keyword |
| azure.graphactivitylogs.properties.is_billable | Specifies whether ingesting the data is billable. When _IsBillable is false ingestion isn't billed to your Azure account. | boolean |
| azure.graphactivitylogs.properties.operation_id | The identifier for the batch. For non-batched requests, this will be unique per request. For batched requests, this will be the same for all requests in the batch. | keyword |
| azure.graphactivitylogs.properties.request_uri | The URI of the request. | keyword |
| azure.graphactivitylogs.properties.roles | The roles in token claims. | keyword |
| azure.graphactivitylogs.properties.scopes | The scopes in token claims. | keyword |
| azure.graphactivitylogs.properties.service_principal_id | The identifier of the servicePrincipal making the request. | keyword |
| azure.graphactivitylogs.properties.sign_in_activity_id | The identifier representing the sign-in activitys. | keyword |
| azure.graphactivitylogs.properties.source_system | The type of agent the event was collected by. For example, OpsManager for Windows agent, either direct connect or Operations Manager, Linux for all Linux agents, or Azure for Azure Diagnostics. | keyword |
| azure.graphactivitylogs.properties.time_generated | The date and time the request was received. | date |
| azure.graphactivitylogs.properties.token_issued_at | The timestamp the token was issued at. | date |
| azure.graphactivitylogs.properties.type | The name of the table. | keyword |
| azure.graphactivitylogs.properties.user_agent | The user agent information related to request. | keyword |
| azure.graphactivitylogs.properties.wids | Denotes the tenant-wide roles assigned to this user. | keyword |
| azure.graphactivitylogs.result_signature | Result signature. | keyword |
| azure.resource.authorization_rule | Authorization rule. | keyword |
| azure.resource.group | Resource group. | keyword |
| azure.resource.id | Resource ID. | keyword |
| azure.resource.name | Name. | keyword |
| azure.resource.namespace | Resource type/namespace. | keyword |
| azure.resource.provider | Resource type/namespace. | keyword |
| azure.subscription_id | Azure subscription ID. | keyword |
| azure.tenant_id | tenant ID. | keyword |
| client.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| client.as.organization.name | Organization name. | keyword |
| client.as.organization.name.text | Multi-field of `client.as.organization.name`. | match_only_text |
| client.geo.city_name | City name. | keyword |
| client.geo.continent_name | Name of the continent. | keyword |
| client.geo.country_iso_code | Country ISO code. | keyword |
| client.geo.country_name | Country name. | keyword |
| client.geo.location.lat | Longitude and latitude. | geo_point |
| client.geo.location.lon | Longitude and latitude. | geo_point |
| client.geo.region_iso_code | Region ISO code. | keyword |
| client.geo.region_name | Region name. | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.user.id | Unique identifier of the user. | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | The cloud project identifier. Examples: Google Cloud Project id, Azure Project id. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host, resource, or service is located. | keyword |
| cloud.service.name | The cloud service name is intended to distinguish services running on different platforms within a provider, eg AWS EC2 vs Lambda, GCP GCE vs App Engine, Azure VM vs App Server. Examples: app engine, app service, cloud run, fargate, lambda. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.geo.region_name | Region name. | keyword |
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
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
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
| http.request.id | A unique identifier for each HTTP request to correlate logs between clients and servers in transactions. The id may be contained in a non-standard HTTP header, such as `X-Request-ID` or `X-Correlation-ID`. | keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.response.bytes | Total size in bytes of the response (body and headers). | long |
| http.response.status_code | HTTP response status code. | long |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
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
| source.geo.location.lat | Longitude and latitude. | geo_point |
| source.geo.location.lon | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.full.text | Multi-field of `url.full`. | match_only_text |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.password | Password of the request. | keyword |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| url.username | Username of the request. | keyword |
| user.id | Unique identifier of the user. | keyword |
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

