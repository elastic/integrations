# Azure App Service Integration

The Azure App Service logs integration retrieves different types of logs categories from Azure App Service.
Azure App Service provides different logging to help you track, monitor, and debug your web application.

- HTTPLogs help monitor application health, performance and usage patterns.
- AuditLogs provide insights when publishing users successfully log on via one of the App Service publishing protocols.
- IPSecAuditLogs are generated through your application and pushed to Azure Monitoring.
- PlatformLogs are generated through AppService platform for your application.
- ConsoleLogs are generated from application or container.
- AppLogs are generated through your application (ex. logging capabilities)

## Data streams

This integration currently collects one data stream:

- App Service Logs

## Requirements

### Credentials

`eventhub` :
_string_
Is the fully managed, real-time data ingestion service.

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
Ex:
https://management.chinacloudapi.cn/ for azure ChinaCloud
https://management.microsoftazure.de/ for azure GermanCloud
https://management.azure.com/ for azure PublicCloud
https://management.usgovcloudapi.net/ for azure USGovernmentCloud
Users can also use this in case of a Hybrid Cloud model, where one may define their own endpoints.

## Setup
To start collecting data with this integration, you need to:
1. Set up an Event Hub namespace and an Event Hub within it. Follow the instructions in the [Azure Event Hubs documentation](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-create).
2. Configure diagnostic settings for your Azure App Service to send logs to the Event Hub. Follow the instructions in the [Azure App Service diagnostic settings documentation](https://learn.microsoft.com/en-us/azure/app-service/monitor-diagnostic-logs#send-diagnostic-logs-to-an-event-hub).
3. Create a Blob Storage account to store the offsets/state of the Event Hub messages. Follow the instructions in the [Azure Blob Storage documentation](https://learn.microsoft.com/en-us/azure/storage/blobs/storage-quickstart-blobs-portal).
4. Configure the integration with the necessary credentials mentioned in the Requirements section.

## App Service Logs
Collects different types of logs from Azure App Service via Event Hub.

An example event for `app_service` looks as following:

```json
{
    "input": {
        "type": "azure-eventhub"
    },
    "agent": {
        "name": "EPGETBIW05AD",
        "id": "e42ad9e7-fc37-4342-80cc-ee5bcb314f5d",
        "ephemeral_id": "65e0aae6-d877-4830-b9f0-10b0ccd39bb9",
        "type": "filebeat",
        "version": "8.18.3"
    },
    "@timestamp": "2025-10-28T09:39:57.805Z",
    "ecs": {
        "version": "8.11.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "azure_app_service.app_service_logs"
    },
    "elastic_agent": {
        "id": "e42ad9e7-fc37-4342-80cc-ee5bcb314f5d",
        "version": "8.18.3",
        "snapshot": false
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-10-28T09:40:37Z",
        "dataset": "azure_app_service.app_service_logs"
    },
    "azure-eventhub": {
        "sequence_number": 133,
        "consumer_group": "$Default",
        "offset": 107374190096,
        "eventhub": "testeventhub",
        "enqueued_time": "2025-10-28T09:40:36.610Z"
    },
    "tags": [
        "azure-appservice",
        "forwarded"
    ],
    "azure": {
        "resource": {
            "id": "/SUBSCRIPTIONS/12CABCB4-86E8-404F-A3D2-1DC9982F45CA/RESOURCEGROUPS/IMERLISHVILI-TEST/PROVIDERS/MICROSOFT.WEB/SITES/LEMON-FLOWER-AF075F43C47545E6B4248C46905E5188"
        },
        "app_service": {
            "result_description": "169.254.129.1 - - [28/Oct/2025:09:39:57 +0000] \"GET /static/favicon.ico HTTP/1.1\" 200 0 \"https://lemon-flower-af075f43c47545e6b4248c46905e5188.azurewebsites.net/\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36\"",
            "level": "Informational",
            "event_stamp_name": "waws-prod-fra-033",
            "operation_name": "Microsoft.Web/sites/log",
            "event_ip_address": "10.30.0.225",
            "event_primary_stamp_name": "waws-prod-fra-033",
            "event_stamp_type": "Stamp",
            "host": "10-30-0-225",
            "location": "Germany West Central",
            "category": "AppServiceConsoleLogs",
            "container_id": "a9ea19c60625_lemon-flower-af075f43c47545e6b4248c46905e5188"
        }
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.app_service.category | The category of the operation. | keyword |
| azure.app_service.container_id | Application container id | keyword |
| azure.app_service.event_ip_address | IP address of the event | keyword |
| azure.app_service.event_primary_stamp_name | Primary name of the service | keyword |
| azure.app_service.event_stamp_name | Name of the service | keyword |
| azure.app_service.event_stamp_type | Values that the service supports | keyword |
| azure.app_service.host | Host where the application is running | keyword |
| azure.app_service.level | Verbosity level of log | keyword |
| azure.app_service.log | Details about the event depending on level | keyword |
| azure.app_service.operation_name | The operation name. | keyword |
| azure.app_service.properties.client_ip | IP address of the client. | ip |
| azure.app_service.properties.client_port | IP address of the client. | long |
| azure.app_service.properties.computer_name | The name of the server on which the log file entry was generated. | keyword |
| azure.app_service.properties.cookie | Cookie on HTTP request. | keyword |
| azure.app_service.properties.cs_bytes | Number of bytes received by server. | long |
| azure.app_service.properties.cs_host | Host name header on HTTP request. | keyword |
| azure.app_service.properties.cs_method |  | keyword |
| azure.app_service.properties.cs_uri_query | URI query on HTTP request. | keyword |
| azure.app_service.properties.cs_uri_stem | The target of the request. | keyword |
| azure.app_service.properties.cs_username | The name of the authenticated user on HTTP request. | keyword |
| azure.app_service.properties.details | Additional information | keyword |
| azure.app_service.properties.protocol | Authentication protocol. | keyword |
| azure.app_service.properties.referer | The site that the user last visited. This site provided a link to the current site. | keyword |
| azure.app_service.properties.result | Success / Failure of HTTP request. | keyword |
| azure.app_service.properties.s_port | Server port number. | keyword |
| azure.app_service.properties.sc_bytes | Number of bytes sent by server. | long |
| azure.app_service.properties.sc_status | HTTP status code. | long |
| azure.app_service.properties.sc_substatus | Substatus error code on HTTP request. | keyword |
| azure.app_service.properties.sc_win32status | Windows status code on HTTP request. | keyword |
| azure.app_service.properties.service_endpoint | This indicates whether the access is via Virtual Network Service Endpoint communication | keyword |
| azure.app_service.properties.source_system | The source system | keyword |
| azure.app_service.properties.time_generated | Time of the Http Request | keyword |
| azure.app_service.properties.time_taken | Time taken by HTTP request in milliseconds. | long |
| azure.app_service.properties.type | The name of the table | keyword |
| azure.app_service.properties.user | Username used for publishing access. | keyword |
| azure.app_service.properties.user_agent | User agent on HTTP request. | keyword |
| azure.app_service.properties.user_display_name | Email address of a user in case publishing was authorized via AAD authentication. | keyword |
| azure.app_service.properties.xazurefdid | X-Azure-FDID header (Azure Frontdoor Id) of the HTTP request | keyword |
| azure.app_service.properties.xfdhealth_probe | X-FD-HealthProbe (Azure Frontdoor Health Probe) of the HTTP request | keyword |
| azure.app_service.properties.xforwarded_for | X-Forwarded-For header of the HTTP request | keyword |
| azure.app_service.properties.xforwarded_host | X-Forwarded-Host header of the HTTP request | keyword |
| azure.app_service.result_description | Log message description | keyword |
| azure.correlation_id | Correlation ID | keyword |
| azure.resource.authorization_rule | Authorization rule | keyword |
| azure.resource.group | Resource group | keyword |
| azure.resource.id | Resource ID | keyword |
| azure.resource.name | Name | keyword |
| azure.resource.namespace | Resource type/namespace | keyword |
| azure.resource.provider | Resource type/namespace | keyword |
| azure.subscription_id | Azure subscription ID | keyword |
| azure.tenant_id | tenant ID | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| geo.city_name | City name. | keyword |
| geo.continent_name | Name of the continent. | keyword |
| geo.country_iso_code | Country ISO code. | keyword |
| geo.country_name | Country name. | keyword |
| geo.location | Longitude and latitude. | geo_point |
| geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| geo.region_iso_code | Region ISO code. | keyword |
| geo.region_name | Region name. | keyword |

