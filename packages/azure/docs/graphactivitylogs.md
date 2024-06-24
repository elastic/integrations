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
        "version": "8.11.0"
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
| client.geo.location.lat | Longitude and latitude. | geo_point |
| client.geo.location.lon | Longitude and latitude. | geo_point |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| source.geo.location.lat | Longitude and latitude. | geo_point |
| source.geo.location.lon | Longitude and latitude. | geo_point |

