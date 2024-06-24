# Azure Application Gateway Logs

Azure Application Gateway Logs capture essential information like access to your gateways (caller's IP, response latency, and more) or security events to detect or prevent threats.

Supported log categories:

| Log Category         | Description                                                                                                                          |
|:-------------------:|:-------------------------------------------------------------------------------------------------------------------------------------:|
| [Access log](https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-diagnostics#access-log)             |  This log can be used to view Application Gateway access patterns and analyze important information. This includes the caller's IP, requested URL, response latency, return code, and bytes in and out. An access log is collected every 60 seconds. This log contains one record per instance of Application Gateway. The Application Gateway instance is identified by the instanceId property.
| [Firewall log](https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-diagnostics#firewall-log)                | This log can be used to view the requests that are logged through either detection or prevention mode of an application gateway that is configured with the web application firewall. Firewall logs are collected every 60 seconds.                                                                                                     |

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

### application_gateway 

The `application_gateway` data stream of the Azure Logs package will collect any Application Gateway log events that have been streamed through an Azure event hub.

An example event for `application_gateway` looks as following:

```json
{
    "@timestamp": "2017-04-26T19:27:38.000Z",
    "azure": {
        "application_gateway": {
            "instance_id": "ApplicationGatewayRole_IN_0",
            "operation_name": "ApplicationGatewayAccess"
        },
        "resource": {
            "group": "PEERINGTEST",
            "id": "/SUBSCRIPTIONS/23103928-B2CF-472A-8CDB-0146E2849129/RESOURCEGROUPS/PEERINGTEST/PROVIDERS/MICROSOFT.NETWORK/APPLICATIONGATEWAYS/Application-Gateway-Name",
            "name": "Application-Gateway-Name",
            "provider": "MICROSOFT.NETWORK/APPLICATIONGATEWAYS"
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
        "address": "www.contoso.com",
        "bytes": 553,
        "domain": "www.contoso.com"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "category": [
            "network"
        ],
        "kind": "event",
        "original": "{\"resourceId\":\"/SUBSCRIPTIONS/23103928-B2CF-472A-8CDB-0146E2849129/RESOURCEGROUPS/PEERINGTEST/PROVIDERS/MICROSOFT.NETWORK/APPLICATIONGATEWAYS/Application-Gateway-Name\",\"operationName\":\"ApplicationGatewayAccess\",\"timestamp\":\"2017-04-26T19:27:38Z\",\"category\":\"ApplicationGatewayAccessLog\",\"properties\":{\"instanceId\":\"ApplicationGatewayRole_IN_0\",\"clientIP\":\"67.43.156.7\",\"clientPort\":46886,\"httpMethod\":\"GET\",\"requestUri\":\"/phpmyadmin/scripts/setup.php\",\"requestQuery\":\"X-AzureApplicationGateway-CACHE-HIT=0&SERVER-ROUTED=10.4.0.4&X-AzureApplicationGateway-LOG-ID=874f1f0f-6807-41c9-b7bc-f3cfa74aa0b1&SERVER-STATUS=404\",\"userAgent\":\"-\",\"httpStatus\":404,\"httpVersion\":\"HTTP/1.0\",\"receivedBytes\":65,\"sentBytes\":553,\"timeTaken\":205,\"sslEnabled\":\"off\",\"host\":\"www.contoso.com\",\"originalHost\":\"www.contoso.com\"}}",
        "type": [
            "connection"
        ]
    },
    "http": {
        "request": {
            "method": "GET"
        },
        "response": {
            "status_code": 404
        },
        "version": "1.0"
    },
    "network": {
        "bytes": 618,
        "protocol": "http"
    },
    "observer": {
        "name": "Application-Gateway-Name",
        "product": "Web Application Firewall",
        "type": "firewall",
        "vendor": "Azure"
    },
    "related": {
        "hosts": [
            "www.contoso.com"
        ],
        "ip": [
            "67.43.156.7"
        ]
    },
    "source": {
        "address": "67.43.156.7",
        "as": {
            "number": 35908
        },
        "bytes": 65,
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.7",
        "port": 46886
    },
    "tags": [
        "preserve_original_event"
    ],
    "url": {
        "domain": "www.contoso.com",
        "path": "/phpmyadmin/scripts/setup.php",
        "query": "X-AzureApplicationGateway-CACHE-HIT=0&SERVER-ROUTED=10.4.0.4&X-AzureApplicationGateway-LOG-ID=874f1f0f-6807-41c9-b7bc-f3cfa74aa0b1&SERVER-STATUS=404"
    }
}
```

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.application_gateway.action | Action taken on the request. Available values are: Blocked and Allowed (for custom rules) Matched (when a rule matches a part of the request) Detected and Blocked (these are both for mandatory rules, depending on if the WAF is in detection or prevention mode). | keyword |
| azure.application_gateway.hostname | Hostname or IP address of the Application Gateway. | keyword |
| azure.application_gateway.instance_id | Application Gateway instance for which firewall data is being generated. For a multiple-instance application gateway, there is one row per instance. | keyword |
| azure.application_gateway.operation_name | Operation name | keyword |
| azure.application_gateway.policy.id | Unique ID of the Firewall Policy associated with the Application Gateway, Listener, or Path. | keyword |
| azure.application_gateway.policy.scope | The location of the policy - values can be "Global", "Listener", or "Location". | keyword |
| azure.application_gateway.policy.scope_name | The name of the object where the policy is applied. | keyword |
| azure.application_gateway.transaction_id | Unique ID for a given transaction which helps group multiple rule violations that occurred within the same request. | keyword |
| azure.correlation_id | Correlation ID | keyword |
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
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |

