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

{{fields "access"}}

## WAF Logs

{{fields "waf"}}
