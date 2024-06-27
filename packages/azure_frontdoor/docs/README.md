# Azure Frontdoor Logs Integration

The azure frontdoor logs integration retrieves different types of log data from AFD.
Azure Front Door provides different logging to help you track, monitor, and debug your Front Door.

- Access logs have detailed information about every request that AFD receives and help you analyze and monitor access patterns, and debug issues.
- Activity logs provide visibility into the operations done on Azure resources.
- Health Probe logs provides the logs for every failed probe to your origin.
- Web Application Firewall (WAF) logs provide detailed information of requests that gets logged through either detection or prevention mode of an Azure Front Door endpoint. A custom domain that gets configured with WAF can also be viewed through these logs.

## Data streams

This integration collects two types of data streams:

- access log
- waf logs

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

## Acceess Logs

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.frontdoor.access.backend_hostname | The host name in the request from client. If you enable custom domains and have wildcard domain (\*.contoso.com), hostname is a.contoso.com. if you use Azure Front Door domain (contoso.azurefd.net), hostname is contoso.azurefd.net. | keyword |
| azure.frontdoor.access.cache_status | Provides the status code of how the request gets handled by the CDN service when it comes to caching. | keyword |
| azure.frontdoor.access.error_info | This field provides detailed info of the error token for each response. | keyword |
| azure.frontdoor.access.is_received_from_client | Boolean value. | boolean |
| azure.frontdoor.access.pop | The edge pop, which responded to the user request. | keyword |
| azure.frontdoor.access.routing_rule_name | The name of the route that the request matched. | keyword |
| azure.frontdoor.access.rules_engine_match_names | The names of the rules that were processed. | keyword |
| azure.frontdoor.access.time | The date and time when the AFD edge delivered requested contents to client (in UTC). | keyword |
| azure.frontdoor.access.time_taken | The length of time from the time AFD edge server receives a client's request to the time that AFD sends the last byte of response to client, in milliseconds. This field doesn't take into account network latency and TCP buffering. | keyword |
| azure.frontdoor.access.time_to_first_byte | The length of time in milliseconds from AFD receives the request to the time the first byte gets sent to client, as measured on Azure Front Door. This property doesn't measure the client data. | keyword |
| azure.frontdoor.category | Azure frontdoor category name. | keyword |
| azure.frontdoor.operation_name | Azure operation name. | keyword |
| azure.frontdoor.resource_id | Azure Resource ID. | keyword |
| azure.frontdoor.tracking_reference | The unique reference string that identifies a request served by AFD, also sent as X-Azure-Ref header to the client. Required for searching details in the access logs for a specific request. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type. | keyword |
| log.offset | Log offset. | long |


## WAF Logs

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.frontdoor.category | Azure frontdoor category name. | keyword |
| azure.frontdoor.operation_name | Azure operation name. | keyword |
| azure.frontdoor.resource_id | Azure Resource ID. | keyword |
| azure.frontdoor.tracking_reference | The unique reference string that identifies a request served by AFD, also sent as X-Azure-Ref header to the client. Required for searching details in the access logs for a specific request. | keyword |
| azure.frontdoor.waf.details.data | Detail data. | keyword |
| azure.frontdoor.waf.details.msg | Detail msg. | keyword |
| azure.frontdoor.waf.policy | WAF policy name. | keyword |
| azure.frontdoor.waf.policy_mode | WAF policy mode. | keyword |
| azure.frontdoor.waf.time | The date and time when the AFD edge delivered requested contents to client (in UTC). | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type. | keyword |
| log.offset | Log offset. | long |

