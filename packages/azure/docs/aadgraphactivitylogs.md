# Azure AD Graph Activity Logs

Azure AD Graph Activity Logs provide an audit trail of all HTTP requests that the legacy Azure AD Graph service (`graph.windows.net`) has received and processed for a tenant. Although Microsoft has deprecated Azure AD Graph in favor of Microsoft Graph, the API is still actively used by Microsoft first-party tooling, older line-of-business applications, third-party SaaS connectors, and adversary tooling (for example ROADtools, AzureHound v1, AADInternals). Refer to the [AADGraphActivityLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadgraphactivitylogs) for the canonical schema.

Tenant administrators can configure the collection and storage destinations of Azure AD Graph Activity Logs through Diagnostic Setting in the Entra Portal. This integration uses Azure Event Hubs destination to stream Azure AD Graph Activity Logs to Elastic.

## Requirements and Setup

### What do I need to use this integration?

The following privileges are required to collect Azure AD Graph Activity Logs:
- A Microsoft Entra ID P1 or P2 tenant license in your tenant.
- A `Security Administrator` or `Global Administrator` Microsoft Entra ID role to configure the diagnostic settings.

### Setup

Refer to the [Azure Logs](https://docs.elastic.co/integrations/azure) page for more information about setting up and using this integration.

### Limitations

- Activities of multi-tenant applications belonging to another tenant are not available.
- In rare cases, events might take up to 2 hours to be delivered to Event Hubs.
- Azure AD Graph is deprecated by Microsoft. New workloads should target Microsoft Graph; this dataset is intended for visibility into legacy traffic that still exists in the tenant.

## Settings

`eventhub` :
  _string_
It is a fully managed, real-time data ingestion service. Elastic recommends using only letters, numbers, and the hyphen (-) character for Event Hub names to maximize compatibility. You _can_ use existing Event Hubs having underscores (_) in the Event Hub name. In this case, the integration will replace underscores with hyphens (-) when it uses the Event Hub name to create dependent Azure resources behind the scenes (for example, the storage account container to store Event Hub consumer offsets). Elastic also recommends using a separate event hub for each log type as the field mappings of each log type differ.
Default value `insights-operational-logs`.

`consumer_group` :
_string_
 The publish/subscribe mechanism of Event Hubs is enabled through consumer groups. A consumer group is a view (state, position, or offset) of an entire event hub. Consumer groups enable multiple consuming applications to each have a separate view of the event stream, and to read the stream independently at their own pace and with their own offsets.
Default value: `$Default`

`connection_string` :
_string_
The connection string required to communicate with Event Hubs, steps [here](https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-get-connection-string).

A Blob Storage account is required to store, retrieve, and update the offset or state of the eventhub messages. This means that after stopping the filebeat azure module it can start back up at the spot that it stopped processing messages.

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
Optional. By default the integration uses the Azure public environment. To override, provide a specific resource manager endpoint to use a different Azure environment.

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

### aadgraphactivitylogs

The `aadgraphactivitylogs` data stream of the Azure Logs package collects Azure AD Graph activity events that have been streamed through an Azure event hub. The events ingest pipeline matches `category == "AzureADGraphActivityLogs"` and sets `event.dataset = azure.aadgraphactivitylogs`. The events data stream's routing rules then reroute the document from `logs-azure.events-*` directly to `logs-azure.aadgraphactivitylogs-*`, where this data stream's pipeline applies full ECS field extraction.

Before this data stream existed, AAD Graph events had no specific override in the events router and fell through to the `azure.platformlogs` catch-all, landing in `logs-azure.platformlogs-default` with only generic platform-log parsing. Those previously-indexed events are not backfilled. Only new events are routed to the dedicated dataset.

An example event for `aadgraphactivitylogs` looks as following:

```json
{
    "@timestamp": "2026-05-07T15:19:33.536Z",
    "azure": {
        "aadgraphactivitylogs": {
            "category": "AzureADGraphActivityLogs",
            "operation_name": "AAD Graph Activity",
            "properties": {
                "actor_type": "User",
                "api_version": "1.6",
                "app_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
                "client_auth_method": 0,
                "direct_access_source": "Gateway",
                "env_cloud_role": "restdirectoryservice",
                "identity_provider": "https://sts.windows.net/ab30785b-417f-42a4-b5dc-8f9051718acb/",
                "scopes": [
                    "62e90394-69f5-4237-9190-012177145e10"
                ],
                "session_id": "5a5a5a5a-5a5a-5a5a-5a5a-5a5a5a5a5a5a",
                "sign_in_activity_id": "AAAAAAAAAAAAAAAAAAAAAA==",
                "time_generated": "2026-05-07T15:19:33.536Z",
                "token_issued_at": "2026-05-07T13:50:39.000Z"
            }
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
        "ip": "81.2.69.143",
        "user": {
            "id": "b37ec517-0a34-4266-b627-f7bb0d679d70"
        }
    },
    "cloud": {
        "account": {
            "id": "ab30785b-417f-42a4-b5dc-8f9051718acb"
        },
        "provider": "azure",
        "region": "WestUS",
        "service": {
            "name": "Azure AD Graph"
        }
    },
    "destination": {
        "geo": {
            "region_name": "WestUS"
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "action": "users-read",
        "category": [
            "iam",
            "web"
        ],
        "duration": 59000000,
        "id": "00000001-0001-0001-0001-000000000001",
        "kind": "event",
        "original": "{\"category\":\"AzureADGraphActivityLogs\",\"location\":\"WestUS\",\"operationName\":\"AAD Graph Activity\",\"properties\":{\"__UDI_RequiredFields_EventTime\":639140000000000000,\"__UDI_RequiredFields_RegionScope\":\"NA\",\"__UDI_RequiredFields_TenantId\":\"ab30785b-417f-42a4-b5dc-8f9051718acb\",\"__UDI_RequiredFields_UniqueId\":\"00000001-0001-0001-0001-000000000001\",\"actorType\":\"User\",\"apiVersion\":\"1.6\",\"appId\":\"04b07795-8ddb-461a-bbee-02f9e1bf7b46\",\"callerIpAddress\":\"81.2.69.143\",\"clientAuthMethod\":0,\"deviceId\":\"\",\"directAccessSource\":\"Gateway\",\"durationMs\":59,\"env_cloud_role\":\"restdirectoryservice\",\"httpMethod\":\"GET\",\"httpStatusCode\":200,\"identityProvider\":\"https://sts.windows.net/ab30785b-417f-42a4-b5dc-8f9051718acb/\",\"issuedAt\":\"5/7/2026 1:50:39 PM\",\"location\":\"WestUS\",\"requestId\":\"00000001-0001-0001-0001-000000000001\",\"requestUri\":\"/v2/ab30785b-417f-42a4-b5dc-8f9051718acb/users\",\"responseSizeBytes\":54662,\"roles\":\"\",\"scopes\":\"62e90394-69f5-4237-9190-012177145e10\",\"servicePrincipalId\":\"\",\"sessionId\":\"5a5a5a5a-5a5a-5a5a-5a5a-5a5a5a5a5a5a\",\"signInActivityId\":\"AAAAAAAAAAAAAAAAAAAAAA==\",\"tenantId\":\"ab30785b-417f-42a4-b5dc-8f9051718acb\",\"timeGenerated\":\"2026-05-07T15:19:33.5368860Z\",\"userAgent\":\"azure-graph-test-client/1.0\",\"userId\":\"b37ec517-0a34-4266-b627-f7bb0d679d70\",\"wids\":\"\"},\"tenantId\":\"ab30785b-417f-42a4-b5dc-8f9051718acb\"}",
        "outcome": "success",
        "type": [
            "access",
            "info"
        ]
    },
    "http": {
        "request": {
            "id": "00000001-0001-0001-0001-000000000001",
            "method": "GET"
        },
        "response": {
            "bytes": 54662,
            "status_code": 200
        }
    },
    "related": {
        "ip": [
            "81.2.69.143"
        ],
        "user": [
            "b37ec517-0a34-4266-b627-f7bb0d679d70",
            "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
        ]
    },
    "session": {
        "id": "5a5a5a5a-5a5a-5a5a-5a5a-5a5a5a5a5a5a"
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
        "original": "/v2/ab30785b-417f-42a4-b5dc-8f9051718acb/users",
        "path": "/v2/ab30785b-417f-42a4-b5dc-8f9051718acb/users"
    },
    "user": {
        "id": "b37ec517-0a34-4266-b627-f7bb0d679d70"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Other",
        "original": "azure-graph-test-client/1.0"
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.aadgraphactivitylogs.category | Azure Event Category. For Azure AD Graph Activity Logs, this is `AzureADGraphActivityLogs`. | keyword |
| azure.aadgraphactivitylogs.operation_name | Operation name. For this category the value is always the literal string `AAD Graph Activity`; rely on the derived `event.action` (HTTP method + directory collection from `requestUri`) for detection. | keyword |
| azure.aadgraphactivitylogs.properties.actor_type | Type of identity that issued the request, for example `User`, `ServicePrincipal`. | keyword |
| azure.aadgraphactivitylogs.properties.api_version | The API version of the event. | keyword |
| azure.aadgraphactivitylogs.properties.app_id | The identifier for the application. | keyword |
| azure.aadgraphactivitylogs.properties.billed_size | The record size in bytes. | double |
| azure.aadgraphactivitylogs.properties.client_auth_method | Indicates how the client was authenticated. For a public client, the value is 0. If client ID and client secret are used, the value is 1. If a client certificate was used for authentication, the value is 2. | integer |
| azure.aadgraphactivitylogs.properties.device_id | The identifier of the device from which the authentication request originated. | keyword |
| azure.aadgraphactivitylogs.properties.direct_access_source | The path through which the request reached the AAD Graph service (for example, `Gateway`). | keyword |
| azure.aadgraphactivitylogs.properties.env_cloud_role | The Microsoft cloud role identifier for the service handling the request (for example, `restdirectoryservice`). Useful for distinguishing first-party Microsoft service traffic from third-party callers. | keyword |
| azure.aadgraphactivitylogs.properties.identity_provider | The identity provider that authenticated the subject of the token. | keyword |
| azure.aadgraphactivitylogs.properties.is_billable | Specifies whether ingesting the data is billable. When _IsBillable is false ingestion isn't billed to your Azure account. | boolean |
| azure.aadgraphactivitylogs.properties.request_uri | The URI of the request. | keyword |
| azure.aadgraphactivitylogs.properties.roles | The roles in token claims. | keyword |
| azure.aadgraphactivitylogs.properties.scopes | The scopes in token claims. | keyword |
| azure.aadgraphactivitylogs.properties.service_principal_id | The identifier of the servicePrincipal making the request. | keyword |
| azure.aadgraphactivitylogs.properties.session_id | The unique identifier for the authentication session. | keyword |
| azure.aadgraphactivitylogs.properties.sign_in_activity_id | Identifier of the Microsoft Entra ID sign-in event that established the authentication context for this AAD Graph request. Correlates this request with an entry in Entra ID Sign-In Logs. | keyword |
| azure.aadgraphactivitylogs.properties.source_system | The type of agent the event was collected by. For example, OpsManager for Windows agent, either direct connect or Operations Manager, Linux for all Linux agents, or Azure for Azure Diagnostics. | keyword |
| azure.aadgraphactivitylogs.properties.time_generated | The date and time the request was received. | date |
| azure.aadgraphactivitylogs.properties.token_issued_at | The timestamp the token was issued at. | date |
| azure.aadgraphactivitylogs.properties.type | The name of the table. | keyword |
| azure.aadgraphactivitylogs.properties.user_agent | The user agent information related to request. | keyword |
| azure.aadgraphactivitylogs.properties.wids | Denotes the tenant-wide roles assigned to this user. | keyword |
| azure.correlation_id | Correlation ID. | keyword |
| azure.resource.authorization_rule | Authorization rule. | keyword |
| azure.resource.group | Resource group. | keyword |
| azure.resource.id | Resource ID. | keyword |
| azure.resource.name | Name. | keyword |
| azure.resource.namespace | Resource type/namespace. | keyword |
| azure.resource.provider | Resource type/namespace. | keyword |
| azure.subscription_id | Azure subscription ID. | keyword |
| azure.tenant_id | tenant ID. | keyword |
| client.geo.location | Longitude and latitude. | geo_point |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.geo.region_name | Region name. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| session.id | The unique identifier for the authentication session. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |

