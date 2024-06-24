# Azure Platform Logs

Platform logs provide detailed diagnostic and auditing information for Azure resources and the Azure platform they depend on.

## Requirements and setup

Refer to the [Azure Logs](https://docs.elastic.co/integrations/azure) page for more information about setting up and using this integration.

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

### platformlogs

The `platformlogs` dataset of the Azure Logs package will collect any platform events that have been streamed through an azure event hub.

An example event for `platformlogs` looks as following:

```json
{
    "@timestamp": "2020-11-05T14:07:32.000Z",
    "agent": {
        "ephemeral_id": "d3c4d56c-e7c7-489e-9d25-683452d16ec9",
        "hostname": "DESKTOP-RFOOE09",
        "id": "c1118415-bcb7-4cf9-b64d-a6c6e8ebcfac",
        "name": "DESKTOP-RFOOE09",
        "type": "filebeat",
        "version": "7.10.0"
    },
    "azure": {
        "platformlogs": {
            "ActivityId": "5890c6fc-fc6b-47cd-971a-2366a1641d99",
            "Caller": "Portal",
            "Environment": "PROD",
            "EventTimeString": "11/5/2020 2:07:32 PM +00:00",
            "ScaleUnit": "PROD-AM3-AZ501",
            "category": "OperationalLogs",
            "event_category": "Administrative",
            "properties": {
                "Namespace": "obstesteventhubs",
                "SubscriptionId": "7657426d-c4c3-44ac-88a2-3b2cd59e6dba",
                "TrackingId": "5890c6fc-fc6b-47cd-971a-2366a1641d99_M8CH3_M8CH3_G8S3",
                "Via": "https://obstesteventhubs.servicebus.windows.net/$Resources/eventhubs?api-version=2017-04&$skip=0&$top=100"
            }
        },
        "resource": {
            "group": "OBS-TEST",
            "id": "/SUBSCRIPTIONS/7657426D-C4C3-44AC-88A2-3B2CD59E6DBA/RESOURCEGROUPS/OBS-TEST/PROVIDERS/MICROSOFT.EVENTHUB/NAMESPACES/OBSTESTEVENTHUBS",
            "name": "OBSTESTEVENTHUBS",
            "provider": "MICROSOFT.EVENTHUB/NAMESPACES"
        },
        "subscription_id": "7657426D-C4C3-44AC-88A2-3B2CD59E6DBA"
    },
    "cloud": {
        "provider": "azure",
        "region": "West Europe"
    },
    "data_stream": {
        "dataset": "azure.platformlogs",
        "namespace": "default",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "02f4e39d-8a1b-4506-a531-b45d0f492ee7",
        "snapshot": false,
        "version": "7.10.0"
    },
    "event": {
        "action": "Retreive Namespace",
        "dataset": "azure.platformlogs",
        "ingested": "2020-11-01T12:02:34.237205200Z",
        "kind": "event",
        "outcome": "succeeded"
    },
    "host": {
        "name": "DESKTOP-RFOOE09"
    }
}
```

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.correlation_id | Correlation ID | keyword |
| azure.platformlogs.ActivityId | ActivityId | keyword |
| azure.platformlogs.Caller | Caller | keyword |
| azure.platformlogs.Cloud | Cloud | keyword |
| azure.platformlogs.Environment | Environment | keyword |
| azure.platformlogs.EventTimeString | EventTimeString | keyword |
| azure.platformlogs.ScaleUnit | ScaleUnit | keyword |
| azure.platformlogs.category | Category | keyword |
| azure.platformlogs.ccpNamespace | ccpNamespace | keyword |
| azure.platformlogs.event_category | Event Category | keyword |
| azure.platformlogs.identity_name | Identity name | keyword |
| azure.platformlogs.operation_name | Operation name | keyword |
| azure.platformlogs.properties | Event properties | flattened |
| azure.platformlogs.result_description | Result description | keyword |
| azure.platformlogs.result_signature | Result signature | keyword |
| azure.platformlogs.result_type | Result type | keyword |
| azure.platformlogs.status | Status | keyword |
| azure.resource.authorization_rule | Authorization rule | keyword |
| azure.resource.group | Resource group | keyword |
| azure.resource.id | Resource ID | keyword |
| azure.resource.name | Name | keyword |
| azure.resource.namespace | Resource type/namespace | keyword |
| azure.resource.provider | Resource type/namespace | keyword |
| azure.subscription_id | Azure subscription ID | keyword |
| azure.tenant_id | tenant ID | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| geo.city_name | City name. | keyword |
| geo.continent_name | Name of the continent. | keyword |
| geo.country_iso_code | Country ISO code. | keyword |
| geo.country_name | Country name. | keyword |
| geo.location | Longitude and latitude. | geo_point |
| geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |

