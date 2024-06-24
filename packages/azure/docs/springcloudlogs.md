# Azure Spring Apps Logs

Azure Spring Apps Logs integration provides insight into the operations of Azure Spring Apps applications.

Users opting for Elastic Cloud native Azure integration can stream the Azure Spring Apps logs directly to their partner solution clusters; you can find more information and steps [here](https://www.elastic.co/guide/en/observability/current/monitor-azure.html).

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

### springappslogs

This is the `springcloudlogs` data stream of the Azure Logs package. It will collect any Spring Apps logs that have been streamed through an azure event hub.

An example event for `springcloudlogs` looks as following:

```json
{
    "@timestamp": "2021-08-03T15:07:03.354Z",
    "agent": {
        "ephemeral_id": "49d0a57c-119c-4a01-878c-d9b06fc81f65",
        "hostname": "docker-fleet-agent",
        "id": "ef999bb2-fe83-4ffa-aa0c-0b54b7598df4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.14.0"
    },
    "azure": {
        "resource": {
            "group": "TESTM",
            "id": "/SUBSCRIPTIONS/0E073EC1-C22F-4488-ADDE-DA35ED609CCD/RESOURCEGROUPS/TESTM/PROVIDERS/MICROSOFT.APPPLATFORM/SPRING/OBSSPRINCLOUD",
            "name": "OBSSPRINCLOUD",
            "provider": "MICROSOFT.APPPLATFORM/SPRING"
        },
        "springcloudlogs": {
            "category": "ApplicationConsole",
            "event_category": "Administrative",
            "log_format": "RAW",
            "logtag": "F",
            "operation_name": "Microsoft.AppPlatform/Spring/logs",
            "properties": {
                "app_name": "helloapp",
                "instance_name": "helloapp-default-8-56df6b7f56-4vr94",
                "service_id": "99070c7524f14eaf970bbdf35f357772",
                "service_name": "obssprincloud",
                "stream": "stdout"
            }
        },
        "subscription_id": "0E073EC1-C22F-4488-ADDE-DA35ED609CCD"
    },
    "cloud": {
        "provider": "azure"
    },
    "data_stream": {
        "dataset": "azure.springcloudlogs",
        "namespace": "default",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ef999bb2-fe83-4ffa-aa0c-0b54b7598df4",
        "snapshot": true,
        "version": "7.14.0"
    },
    "event": {
        "action": "Microsoft.AppPlatform/Spring/logs",
        "agent_id_status": "verified",
        "dataset": "azure.springcloudlogs",
        "ingested": "2021-08-03T15:15:14.386889100Z",
        "kind": "event"
    },
    "geo": {
        "name": "westeurope"
    },
    "log": {
        "level": "Informational"
    },
    "message": "2021-08-03 15:07:03.354  INFO [helloapp,,,] 1 --- [trap-executor-0] c.n.d.s.r.aws.ConfigClusterResolver      : Resolving eureka endpoints via configuration",
    "tags": [
        "azure-springcloudlogs"
    ]
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
| azure.springcloudlogs.category | Category | keyword |
| azure.springcloudlogs.event_category | Event Category | keyword |
| azure.springcloudlogs.log_format | ccpNamespace | keyword |
| azure.springcloudlogs.logtag | Cloud | keyword |
| azure.springcloudlogs.operation_name | Operation name | keyword |
| azure.springcloudlogs.properties.app_name | Application name | keyword |
| azure.springcloudlogs.properties.instance_name | Instance name | keyword |
| azure.springcloudlogs.properties.logger | Logger | keyword |
| azure.springcloudlogs.properties.service_id | Service ID | keyword |
| azure.springcloudlogs.properties.service_name | Service name | keyword |
| azure.springcloudlogs.properties.stack | Stack name | keyword |
| azure.springcloudlogs.properties.stream | Stream | keyword |
| azure.springcloudlogs.properties.thread | Thread | keyword |
| azure.springcloudlogs.properties.type | Type | keyword |
| azure.springcloudlogs.status | Status | keyword |
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

