# Azure Activity Logs

Azure Activity Logs provide insight into the operations on each Azure resource in the subscription. Use the Activity log to determine the what, who, and when for any write operations taken on the resources in your subscription.

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

### activitylogs

The `activitylogs` data stream of the Azure Logs package will collect any activity events that have been streamed through an azure event hub.

An example event for `activitylogs` looks as following:

```json
{
    "@timestamp": "2020-11-02T08:51:36.997Z",
    "azure": {
        "activitylogs": {
            "category": "Administrative",
            "event_category": "Administrative",
            "identity": {
                "authorization": {
                    "action": "Microsoft.Resources/deployments/write",
                    "evidence": {
                        "principal_id": "68b1adf93eb744b08eb8ce96522a08d3",
                        "principal_type": "User",
                        "role": "Owner",
                        "role_assignment_id": "7f06f09dd6764b44930adbec3f10e92b",
                        "role_assignment_scope": "/providers/Microsoft.Management/managementGroups/5341238b-665c-4eb4-b259-b250371ae430",
                        "role_definition_id": "8e3af657a8ff443ca75c2fe8c4bcb635"
                    },
                    "scope": "/subscriptions/3f041b6d-fc31-41d8-8ff6-e5f16e6747ff/resourceGroups/obs-test/providers/Microsoft.Resources/deployments/NoMarketplace"
                },
                "claims": {
                    "aio": "ATQAy/8RAAAAsL67UQMOHZv3izTDRJfvJN5UyON9ktUszzPj08K8aURsbhxhR0niz9s1Pxm9U1lI",
                    "appid": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
                    "appidacr": "2",
                    "aud": "https://management.core.windows.net/",
                    "exp": "1604310019",
                    "groups": "644c6686-9ef1-4b69-9410-107664a9e1f0,9ed1993c-ce9c-4915-a04d-58c6f5f7ee12",
                    "http://schemas_microsoft_com/claims/authnclassreference": "1",
                    "http://schemas_microsoft_com/claims/authnmethodsreferences": "pwd",
                    "http://schemas_microsoft_com/identity/claims/objectidentifier": "68b1adf9-3eb7-44b0-8eb8-ce96522a08d3",
                    "http://schemas_microsoft_com/identity/claims/scope": "user_impersonation",
                    "http://schemas_microsoft_com/identity/claims/tenantid": "4fa94b7d-a743-486f-abcc-6c276c44cf4b",
                    "http://schemas_xmlsoap_org/ws/2005/05/identity/claims/givenname": "John",
                    "http://schemas_xmlsoap_org/ws/2005/05/identity/claims/name": "john@gmail.com",
                    "http://schemas_xmlsoap_org/ws/2005/05/identity/claims/nameidentifier": "a9L2WR3XZN5ANzAqwLx_4aamU49JG6kqaE5JZkXdeNs",
                    "http://schemas_xmlsoap_org/ws/2005/05/identity/claims/surname": "Doe",
                    "http://schemas_xmlsoap_org/ws/2005/05/identity/claims/upn": "john@gmail.com",
                    "iat": "1604306119",
                    "ipaddr": "77.170.179.229",
                    "iss": "https://sts.windows.net/4fa94b7d-a743-486f-abcc-6c276c44cf4b/",
                    "nbf": "1604306119",
                    "puid": "1003200045B17AD4",
                    "rh": "0.AAAAfUupT0Onb0irzGwnbETPS4NAS8SwO8FJtH2XTlPL3zxRAA8.",
                    "uti": "rqr63RW_Kk6ztuomENMQAA",
                    "ver": "1.0",
                    "wids": "5d6b6bb7-de71-4623-b4af-96380a352509",
                    "xms_tcdt": "1469565974"
                },
                "claims_initiated_by_user": {
                    "schema": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims"
                }
            },
            "operation_name": "MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE",
            "result_signature": "Succeeded.",
            "result_type": "Success"
        },
        "correlation_id": "876190b4-5b99-4a39-b725-4f5644911cf0",
        "resource": {
            "group": "OBS-TEST",
            "id": "/SUBSCRIPTIONS/3f041b6d-fc31-41d8-8ff6-e5f16e6747ff/RESOURCEGROUPS/OBS-TEST/PROVIDERS/MICROSOFT.RESOURCES/DEPLOYMENTS/NOMARKETPLACE",
            "name": "NOMARKETPLACE",
            "provider": "MICROSOFT.RESOURCES/DEPLOYMENTS"
        },
        "subscription_id": "3f041b6d-fc31-41d8-8ff6-e5f16e6747ff"
    },
    "cloud": {
        "provider": "azure"
    },
    "data_stream": {
        "dataset": "azure.activitylogs",
        "namespace": "default",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "action": "MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE",
        "dataset": "azure.activitylogs",
        "duration": 0,
        "ingested": "2020-10-30T20:47:48.123859400Z",
        "kind": "event",
        "outcome": "success"
    },
    "log": {
        "level": "Information"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.activitylogs.category | Category | keyword |
| azure.activitylogs.event_category | Event Category | keyword |
| azure.activitylogs.identity.authorization.action | Action | keyword |
| azure.activitylogs.identity.authorization.evidence.principal_id | Principal ID | keyword |
| azure.activitylogs.identity.authorization.evidence.principal_type | Principal type | keyword |
| azure.activitylogs.identity.authorization.evidence.role | Role | keyword |
| azure.activitylogs.identity.authorization.evidence.role_assignment_id | Role assignment ID | keyword |
| azure.activitylogs.identity.authorization.evidence.role_assignment_scope | Role assignment scope | keyword |
| azure.activitylogs.identity.authorization.evidence.role_definition_id | Role definition ID | keyword |
| azure.activitylogs.identity.authorization.scope | Scope | keyword |
| azure.activitylogs.identity.claims.\* | Claims | object |
| azure.activitylogs.identity.claims_initiated_by_user.fullname | Fullname | keyword |
| azure.activitylogs.identity.claims_initiated_by_user.givenname | Givenname | keyword |
| azure.activitylogs.identity.claims_initiated_by_user.name | Name | keyword |
| azure.activitylogs.identity.claims_initiated_by_user.schema | Schema | keyword |
| azure.activitylogs.identity.claims_initiated_by_user.surname | Surname | keyword |
| azure.activitylogs.identity_name | identity name | keyword |
| azure.activitylogs.level | Level | long |
| azure.activitylogs.operation_name | Operation name | keyword |
| azure.activitylogs.operation_version | Operation version | keyword |
| azure.activitylogs.properties | Event properties | flattened |
| azure.activitylogs.result_signature | Result signature | keyword |
| azure.activitylogs.result_type | Result type | keyword |
| azure.activitylogs.tenant_id | Tenant ID | keyword |
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
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |

