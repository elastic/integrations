# Azure Firewall Logs

Azure Firewall Logs are records of events such as network and application rules that occur within your Azure Firewalls. They provide visibility and can be used to troubleshoot issues related to access, conectivity or performance.

Supported log categories:

| Log Category                 | Description                                                                                                                          |
|:----------------------------:|:------------------------------------------------------------------------------------------------------------------------------------:|
| AzureFirewallApplicationRule | These logs capture information about the traffic that is allowed or denied by application rules configured in Azure Firewall.        |
| AzureFirewallNetworkRule     | These logs capture information about the traffic that is allowed or denied by network rules configured in Azure Firewall.            |
| AzureFirewallDnsProxy        | These logs capture information about DNS requests and responses that are processed by Azure Firewall's DNS proxy.                    |

## Requirements and setup

Refer to the [Azure Logs](https://docs.elastic.co/integrations/azure) page for more information about setting up and using this integration.

## Settings

`eventhub` :
  _string_
An Event Hub is a fully managed, real-time data ingestion service. Elastic recommends using only letters, numbers, and the hyphen (-) character for Event Hub names to maximize compatibility. You can use existing Event Hubs having underscores (_) in the Event Hub name; in this case, the integration will replace underscores with hyphens (-) when it uses the Event Hub name to create dependent Azure resources behind the scenes (e.g., the storage account container to store Event Hub consumer offsets). Elastic also recommends using a separate event hub for each log type as the field mappings of each log type differ.
Default value `insights-operational-logs`.

`consumer_group` :
_string_
 The publish/subscribe mechanism of Event Hubs is enabled through consumer groups. A consumer group is a view (state, position, or offset) of an entire event hub. Consumer groups enable multiple consuming applications to each have a separate view of the event stream, and to read the stream independently at their own pace and with their own offsets.
Default value: `$Default`

`connection_string` :
_string_
The connection string is required to communicate with Event Hubs, see steps [here](https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-get-connection-string).

A Blob Storage account is required in order to store/retrieve/update the offset or state of the eventhub messages. This means that after stopping the Azure logs package it can start back up at the spot that it stopped processing messages.

`storage_account` :
_string_
The name of the storage account where the state/offsets will be stored and updated.

`storage_account_key` :
_string_
The storage account key, this key will be used to authorize access to data in your storage account.

`storage_account_container` :
_string_
The storage account container where the integration stores the checkpoint data for the consumer group. It is an advanced option to use with extreme care. You MUST use a dedicated storage account container for each Azure log type (activity, sign-in, audit logs, and others). DO NOT REUSE the same container name for more than one Azure log type. See [Container Names](https://docs.microsoft.com/en-us/rest/api/storageservices/naming-and-referencing-containers--blobs--and-metadata#container-names) for details on naming rules from Microsoft. The integration generates a default container name if not specified.

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

### firewall_logs 

The `firewall_logs` data stream of the Azure Logs package will collect any firewall log events that have been streamed through an Azure event hub.

An example event for `firewall` looks as following:

```json
{
    "@timestamp": "2022-06-08T16:54:58.849Z",
    "azure": {
        "firewall": {
            "action": "Deny",
            "category": "AzureFirewallNetworkRule",
            "icmp": {
                "request": {
                    "code": "8"
                }
            },
            "operation_name": "AzureFirewallNetworkRuleLog"
        },
        "resource": {
            "group": "TEST-FW-RG",
            "id": "/SUBSCRIPTIONS/23103928-B2CF-472A-8CDB-0146E2849129/RESOURCEGROUPS/TEST-FW-RG/PROVIDERS/MICROSOFT.NETWORK/AZUREFIREWALLS/TEST-FW01",
            "name": "TEST-FW01",
            "provider": "MICROSOFT.NETWORK/AZUREFIREWALLS"
        },
        "subscription_id": "23103928-B2CF-472A-8CDB-0146E2849129"
    },
    "cloud": {
        "account": {
            "id": "23103928-B2CF-472A-8CDB-0146E2849129"
        },
        "provider": "azure"
    },
    "destination": {
        "address": "89.160.20.156",
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.156"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "category": [
            "network"
        ],
        "kind": "event",
        "original": "{\"category\":\"AzureFirewallNetworkRule\",\"operationName\":\"AzureFirewallNetworkRuleLog\",\"properties\":{\"msg\":\"ICMP Type=8 request from 192.168.0.2 to 89.160.20.156. Action: Deny. \"},\"resourceId\":\"/SUBSCRIPTIONS/23103928-B2CF-472A-8CDB-0146E2849129/RESOURCEGROUPS/TEST-FW-RG/PROVIDERS/MICROSOFT.NETWORK/AZUREFIREWALLS/TEST-FW01\",\"time\":\"2022-06-08T16:54:58.8492560Z\"}",
        "type": [
            "connection",
            "denied"
        ]
    },
    "network": {
        "transport": "icmp"
    },
    "observer": {
        "name": "TEST-FW01",
        "product": "Network Firewall",
        "type": "firewall",
        "vendor": "Azure"
    },
    "related": {
        "ip": [
            "192.168.0.2",
            "89.160.20.156"
        ]
    },
    "source": {
        "address": "192.168.0.2",
        "ip": "192.168.0.2"
    },
    "tags": [
        "preserve_original_event"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.correlation_id | Correlation ID | keyword |
| azure.firewall.action | Firewall action taken | keyword |
| azure.firewall.category | Category | keyword |
| azure.firewall.dnssec_bool_flag | True if DNS request is using DNSSEC | boolean |
| azure.firewall.dnssec_buffer_size | Size of the DNSSEC buffer | long |
| azure.firewall.duration | Duration of the firewall request | keyword |
| azure.firewall.event_original_uid | UID assigned to the logged event | keyword |
| azure.firewall.icmp.request.code | ICMP request code | keyword |
| azure.firewall.identity_name | identity name | keyword |
| azure.firewall.operation_name | Operation name | keyword |
| azure.firewall.policy | Name of firewall policy containing the matched rule | keyword |
| azure.firewall.rule_collection_group | Name of rule collection group containing the matched rule  - name: icmp | keyword |
| azure.resource.authorization_rule | Authorization rule | keyword |
| azure.resource.group | Resource group | keyword |
| azure.resource.id | Resource ID | keyword |
| azure.resource.name | Name | keyword |
| azure.resource.namespace | Resource type/namespace | keyword |
| azure.resource.provider | Resource type/namespace | keyword |
| azure.subscription_id | Azure subscription ID | keyword |
| azure.tenant_id | tenant ID | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dns.response_code |  |  |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| geo.city_name | City name. | keyword |
| geo.continent_name | Name of the continent. | keyword |
| geo.country_iso_code | Country ISO code. | keyword |
| geo.country_name | Country name. | keyword |
| geo.location | Longitude and latitude. | geo_point |
| geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| geo.region_iso_code | Region ISO code. | keyword |
| geo.region_name | Region name. | keyword |

