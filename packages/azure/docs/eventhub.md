# Azure Event Hub Input

The Azure Event Hub Input integration is a generic integration that allows you to collect log categories from Azure services using Azure Event Hubs.

The azure-eventhub input uses the [Event Processor Host](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-event-processor-host). EPH can run across multiple processes and machines while load-balancing message consumers. More on this in the [Azure event-hubs-go doc](https://github.com/Azure/azure-event-hubs-go#event-processor-host) and [Azure event-processor doc](https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-event-processor-host)). 

EPH state, such as leases on partitions and checkpoints in the event stream, is shared between receivers using an Azure Storage container.
 For this reason, users will have to create or use an existing storage account as a prerequisite to using this input.

## Requirements and setup

Refer to the [Azure Logs](https://docs.elastic.co/integrations/azure) page for more information about setting up and using this integration.

## Settings

`eventhub` :
  _string_
It is a fully managed, real-time data ingestion service. Elastic recommends using only letters, numbers, and the hyphen (-) character for Event Hub names to maximize compatibility. You can use existing Event Hubs having underscores (_) in the Event Hub name; in this case, the integration will replace underscores with hyphens (-) when it uses the Event Hub name to create dependent Azure resources behind the scenes (e.g., the storage account container to store Event Hub consumer offsets). Elastic also recommends using a separate event hub for each log type as the field mappings of each log type differ.

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

### eventhub

The `eventhub` data stream of the Azure Logs package will collect any events that have been streamed through an azure event hub.

An example event for `eventhub` looks as following:

```json
{
    "@timestamp": "2021-10-18T12:31:17.027Z",
    "agent": {
        "ephemeral_id": "42a183d5-df19-4008-8776-d9765bc01d50",
        "hostname": "docker-fleet-agent",
        "id": "b659ebed-5338-45f3-9762-1bcf2c1ad0e1",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.15.0"
    },
    "azure-eventhub": {
        "consumer_group": "$Default",
        "enqueued_time": "2021-10-15T09:14:25.419Z",
        "eventhub": "insights-activity-logs",
        "offset": 274878093752,
        "sequence_number": 1215
    },
    "data_stream": {
        "dataset": "azure.eventhub",
        "namespace": "default",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "b659ebed-5338-45f3-9762-1bcf2c1ad0e1",
        "snapshot": true,
        "version": "7.15.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "azure.eventhub",
        "ingested": "2021-10-18T12:31:17Z",
        "kind": "event"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "6505f7ca36739e7eb909bdb52bf3ec18",
        "ip": [
            "172.27.0.7"
        ],
        "mac": [
            "02:42:ac:1b:00:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "4.19.128-microsoft-standard",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "input": {
        "type": "azure-eventhub"
    },
    "message": "{\\\"ReleaseVersion\\\":\\\"6.2021.39.11+d1f0e29.release_2021w39_az\\\",\\\"RoleLocation\\\":\\\"North Europe\\\",\\\"callerIpAddress\\\":\\\"77.170.179.229\\\",\\\"category\\\":\\\"Administrative\\\",\\\"correlationId\\\":\\\"a75a0752-ebbb-42bf-831f-43788a8c1193\\\",\\\"durationMs\\\":\\\"0\\\",\\\"identity\\\":{\\\"authorization\\\":{\\\"action\\\":\\\"Microsoft.ServiceBus\\/namespaces\\/delete\\\",\\\"evidence\\\":{\\\"principalId\\\":\\\"68b1adf93eb744b08eb8ce96522a08d3\\\",\\\"principalType\\\":\\\"User\\\",\\\"role\\\":\\\"Owner\\\",\\\"roleAssignmentId\\\":\\\"7f06f09dd6764b44930adbec3f10e92b\\\",\\\"roleAssignmentScope\\\":\\\"\\/providers\\/Microsoft.Management\\/managementGroups\\/5341238b-665c-4eb4-b259-b250371ae430\\\",\\\"roleDefinitionId\\\":\\\"8e3af657a8ff443ca75c2fe8c4bcb635\\\"},\\\"scope\\\":\\\"\\/subscriptions\\/7657426d-c4c3-44ac-88a2-3b2cd59e6dba\\/resourcegroups\\/obs-test\\/providers\\/Microsoft.ServiceBus\\/namespaces\\/testobs\\\"},\\\"claims\\\":{\\\"aio\\\":\\\"ATQAy\\/8TAAAAgFUjNWoJWKgHlAK2AL92UMeUsb6VD5zck\\/myDZPucX5V3Gc8SDMg5vTV28NUy5N7\\\",\\\"appid\\\":\\\"c44b4083-3bb0-49c1-b47d-974e53cbdf3c\\\",\\\"appidacr\\\":\\\"2\\\",\\\"aud\\\":\\\"https:\\/\\/management.core.windows.net\\/\\\",\\\"exp\\\":\\\"1634290798\\\",\\\"groups\\\":\\\"644c6686-9ef1-4b69-9410-107664a9e1f0,9ed1993c-ce9c-4915-a04d-58c6f5f7ee12,a953f548-26ab-47b2-be7d-65586b7bcc2a\\\",\\\"http:\\/\\/schemas.microsoft.com\\/2012\\/01\\/devicecontext\\/claims\\/identifier\\\":\\\"1060004c-63dc-465b-b868-ec6547176c58\\\",\\\"http:\\/\\/schemas.microsoft.com\\/claims\\/authnclassreference\\\":\\\"1\\\",\\\"http:\\/\\/schemas.microsoft.com\\/claims\\/authnmethodsreferences\\\":\\\"pwd,rsa\\\",\\\"http:\\/\\/schemas.microsoft.com\\/identity\\/claims\\/objectidentifier\\\":\\\"68b1adf9-3eb7-44b0-8eb8-ce96522a08d3\\\",\\\"http:\\/\\/schemas.microsoft.com\\/identity\\/claims\\/scope\\\":\\\"user_impersonation\\\",\\\"http:\\/\\/schemas.microsoft.com\\/identity\\/claims\\/tenantid\\\":\\\"4fa94b7d-a743-486f-abcc-6c276c44cf4b\\\",\\\"http:\\/\\/schemas.xmlsoap.org\\/ws\\/2005\\/05\\/identity\\/claims\\/givenname\\\":\\\"Mariana\\\",\\\"http:\\/\\/schemas.xmlsoap.org\\/ws\\/2005\\/05\\/identity\\/claims\\/name\\\":\\\"mariana@elastic.co\\\",\\\"http:\\/\\/schemas.xmlsoap.org\\/ws\\/2005\\/05\\/identity\\/claims\\/nameidentifier\\\":\\\"a9L2WR3XZN5ANzAqwLx_4aamU49JG6kqaE5JZkXdeNs\\\",\\\"http:\\/\\/schemas.xmlsoap.org\\/ws\\/2005\\/05\\/identity\\/claims\\/surname\\\":\\\"Dima\\\",\\\"http:\\/\\/schemas.xmlsoap.org\\/ws\\/2005\\/05\\/identity\\/claims\\/upn\\\":\\\"mariana@elastic.co\\\",\\\"iat\\\":\\\"1634286898\\\",\\\"ipaddr\\\":\\\"77.170.179.229\\\",\\\"iss\\\":\\\"https:\\/\\/sts.windows.net\\/4fa94b7d-a743-486f-abcc-6c276c44cf4b\\/\\\",\\\"name\\\":\\\"Mariana Dima\\\",\\\"nbf\\\":\\\"1634286898\\\",\\\"puid\\\":\\\"1003200045B17AD4\\\",\\\"rh\\\":\\\"0.AVEAfUupT0Onb0irzGwnbETPS4NAS8SwO8FJtH2XTlPL3zxRAA8.\\\",\\\"uti\\\":\\\"yUcYeZwj9EWeA-rTCtRwAA\\\",\\\"ver\\\":\\\"1.0\\\",\\\"wids\\\":\\\"5d6b6bb7-de71-4623-b4af-96380a352509\\\",\\\"xms_tcdt\\\":\\\"1469565974\\\"}},\\\"level\\\":\\\"Information\\\",\\\"operationName\\\":\\\"MICROSOFT.SERVICEBUS\\/NAMESPACES\\/DELETE\\\",\\\"properties\\\":{\\\"entity\\\":\\\"\\/subscriptions\\/7657426d-c4c3-44ac-88a2-3b2cd59e6dba\\/resourcegroups\\/obs-test\\/providers\\/Microsoft.ServiceBus\\/namespaces\\/testobs\\\",\\\"eventCategory\\\":\\\"Administrative\\\",\\\"hierarchy\\\":\\\"4fa94b7d-a743-486f-abcc-6c276c44cf4b\\/5341238b-665c-4eb4-b259-b250371ae430\\/7657426d-c4c3-44ac-88a2-3b2cd59e6dba\\\",\\\"message\\\":\\\"Microsoft.ServiceBus\\/namespaces\\/delete\\\"},\\\"resourceId\\\":\\\"\\/SUBSCRIPTIONS\\/7657426D-C4C3-44AC-88A2-3B2CD59E6DBA\\/RESOURCEGROUPS\\/OBS-TEST\\/PROVIDERS\\/MICROSOFT.SERVICEBUS\\/NAMESPACES\\/TESTOBS\\\",\\\"resultSignature\\\":\\\"Started.\\\",\\\"resultType\\\":\\\"Start\\\",\\\"tenantId\\\":\\\"4fa94b7d-a743-486f-abcc-6c276c44cf4b\\\",\\\"time\\\":\\\"2021-10-15T09:08:29.9268177Z\\\"}\\r\\n",
    "tags": [
        "azure-eventhub"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure-eventhub.consumer_group | consumer group | keyword |
| azure-eventhub.enqueued_time | The enqueued time. | keyword |
| azure-eventhub.eventhub | Event hub name. | keyword |
| azure-eventhub.offset | Offset | long |
| azure-eventhub.partition_id | Partition ID | keyword |
| azure-eventhub.sequence_number | Sequence number | long |
| azure.correlation_id | Correlation ID | keyword |
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
| event.module | Event module | constant_keyword |
| geo.city_name | City name. | keyword |
| geo.continent_name | Name of the continent. | keyword |
| geo.country_iso_code | Country ISO code. | keyword |
| geo.country_name | Country name. | keyword |
| geo.location | Longitude and latitude. | geo_point |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |

