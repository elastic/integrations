# Azure Integration

The azure integration retrieves different types of log data from Azure.
There are several requirements before using the module since the logs will actually be read from azure event hubs.

   - the logs have to be exported first to the event hub https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-create-kafka-enabled
   - to export activity logs to event hubs users can follow the steps here https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-export
   - to export audit and sign-in logs to event hubs users can follow the steps here https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/tutorial-azure-monitor-stream-logs-to-event-hub

The module contains the following filesets:

### activitylogs
Will retrieve azure activity logs. Control-plane events on Azure Resource Manager resources. Activity logs provide insight into the operations that were performed on resources in your subscription.

### platformlogs
Will retrieve azure platform logs. Platform logs provide detailed diagnostic and auditing information for Azure resources and the Azure platform they depend on.

### signinlogs 
Will retrieve azure Active Directory sign-in logs. The sign-ins report provides information about the usage of managed applications and user sign-in activities.

### auditlogs 
Will retrieve azure Active Directory audit logs. The audit logs provide traceability through logs for all changes done by various features within Azure AD. Examples of audit logs include changes made to any resources within Azure AD like adding or removing users, apps, groups, roles and policies.

### Credentials

`eventhub` :
  _string_
Is the fully managed, real-time data ingestion service.
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

`resource_manager_endpoint` :
_string_
Optional, by default we are using the azure public environment, to override, users can provide a specific resource manager endpoint in order to use a different azure environment.
Ex:
https://management.chinacloudapi.cn/ for azure ChinaCloud
https://management.microsoftazure.de/ for azure GermanCloud
https://management.azure.com/ for azure PublicCloud
https://management.usgovcloudapi.net/ for azure USGovernmentCloud
Users can also use this in case of a Hybrid Cloud model, where one may define their own endpoints.


An example event for `activitylogs` looks as following:

```$json
{
    "_index": ".ds-logs-azure.activitylogs-default-000001",
    "_type": "_doc",
    "_id": "bQlEe3UBm_qs2Y3aNZPq",
    "_score": null,
    "_source": {
        "log": {
            "level": "Information"
        },
        "azure-eventhub": {
            "sequence_number": 643,
            "consumer_group": "$Default",
            "offset": 107374182400,
            "eventhub": "insights-activity-logs",
            "enqueued_time": "2020-11-02T08:59:38.905Z"
        },
        "tags": [
            "forwarded"
        ],
        "cloud": {
            "provider": "azure"
        },
        "input": {
            "type": "azure-eventhub"
        },
        "@timestamp": "2020-11-02T08:51:36.997Z",
        "ecs": {
            "version": "1.5.0"
        },
        "data_stream": {
            "namespace": "default",
            "type": "logs",
            "dataset": "azure.activitylogs"
        },
        "event": {
            "duration": "0",
            "ingested": "2020-10-30T20:47:48.123859400Z",
            "kind": "event",
            "action": "MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE",
            "dataset": "azure.activitylogs",
            "outcome": "success"
        },
        "azure": {
            "subscription_id": "3f041b6d-fc31-41d8-8ff6-e5f16e6747ff",
            "resource": {
                "provider": "MICROSOFT.RESOURCES/DEPLOYMENTS",
                "name": "NOMARKETPLACE",
                "id": "/SUBSCRIPTIONS/3f041b6d-fc31-41d8-8ff6-e5f16e6747ff/RESOURCEGROUPS/OBS-TEST/PROVIDERS/MICROSOFT.RESOURCES/DEPLOYMENTS/NOMARKETPLACE",
                "group": "OBS-TEST"
            },
            "correlation_id": "876190b4-5b99-4a39-b725-4f5644911cf0",
            "activitylogs": {
                "operation_name": "MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE",
                "result_type": "Success",
                "identity": {
                    "authorization": {
                        "evidence": {
                            "role_definition_id": "8e3af657a8ff443ca75c2fe8c4bcb635",
                            "role": "Owner",
                            "role_assignment_scope": "/providers/Microsoft.Management/managementGroups/5341238b-665c-4eb4-b259-b250371ae430",
                            "role_assignment_id": "7f06f09dd6764b44930adbec3f10e92b",
                            "principal_type": "User",
                            "principal_id": "68b1adf93eb744b08eb8ce96522a08d3"
                        },
                        "scope": "/subscriptions/3f041b6d-fc31-41d8-8ff6-e5f16e6747ff/resourceGroups/obs-test/providers/Microsoft.Resources/deployments/NoMarketplace",
                        "action": "Microsoft.Resources/deployments/write"
                    },
                    "claims": {
                        "xms_tcdt": "1469565974",
                        "aio": "ATQAy/8RAAAAsL67UQMOHZv3izTDRJfvJN5UyON9ktUszzPj08K8aURsbhxhR0niz9s1Pxm9U1lI",
                        "iss": "https://sts.windows.net/4fa94b7d-a743-486f-abcc-6c276c44cf4b/",
                        "http://schemas_xmlsoap_org/ws/2005/05/identity/claims/nameidentifier": "a9L2WR3XZN5ANzAqwLx_4aamU49JG6kqaE5JZkXdeNs",
                        "http://schemas_xmlsoap_org/ws/2005/05/identity/claims/surname": "Doe",
                        "http://schemas_microsoft_com/identity/claims/scope": "user_impersonation",
                        "http://schemas_microsoft_com/identity/claims/tenantid": "4fa94b7d-a743-486f-abcc-6c276c44cf4b",
                        "puid": "1003200045B17AD4",
                        "wids": "5d6b6bb7-de71-4623-b4af-96380a352509",
                        "http://schemas_microsoft_com/claims/authnclassreference": "1",
                        "exp": "1604310019",
                        "ipaddr": "77.170.179.229",
                        "iat": "1604306119",
                        "http://schemas_microsoft_com/identity/claims/objectidentifier": "68b1adf9-3eb7-44b0-8eb8-ce96522a08d3",
                        "http://schemas_microsoft_com/claims/authnmethodsreferences": "pwd",
                        "ver": "1.0",
                        "groups": "644c6686-9ef1-4b69-9410-107664a9e1f0,9ed1993c-ce9c-4915-a04d-58c6f5f7ee12",
                        "uti": "rqr63RW_Kk6ztuomENMQAA",
                        "http://schemas_xmlsoap_org/ws/2005/05/identity/claims/upn": "john@gmail.com",
                        "aud": "https://management.core.windows.net/",
                        "nbf": "1604306119",
                        "appidacr": "2",
                        "rh": "0.AAAAfUupT0Onb0irzGwnbETPS4NAS8SwO8FJtH2XTlPL3zxRAA8.",
                        "appid": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
                        "http://schemas_xmlsoap_org/ws/2005/05/identity/claims/givenname": "John",
                        "http://schemas_xmlsoap_org/ws/2005/05/identity/claims/name": "john@gmail.com"
                    },
                    "claims_initiated_by_user": {
                        "schema": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims"
                    }
                },
                "category": "Administrative",
                "event_category": "Administrative",
                "result_signature": "Succeeded.",
                "properties": {
                    "eventCategory": "Administrative",
                    "hierarchy": "",
                    "message": "Microsoft.Resources/deployments/write",
                    "entity": "/subscriptions/3f041b6d-fc31-41d8-8ff6-e5f16e6747ff/resourceGroups/obs-test/providers/Microsoft.Resources/deployments/NoMarketplace"
                }
            }
        }
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
| azure.activitylogs.identity.claims.* | Claims | object |
| azure.activitylogs.identity.claims_initiated_by_user.fullname | Fullname | keyword |
| azure.activitylogs.identity.claims_initiated_by_user.givenname | Givenname | keyword |
| azure.activitylogs.identity.claims_initiated_by_user.name | Name | keyword |
| azure.activitylogs.identity.claims_initiated_by_user.schema | Schema | keyword |
| azure.activitylogs.identity.claims_initiated_by_user.surname | Surname | keyword |
| azure.activitylogs.operation_name | Operation name | keyword |
| azure.activitylogs.properties.service_request_id | Service Request Id | keyword |
| azure.activitylogs.properties.status_code | Status code | keyword |
| azure.activitylogs.result_signature | Result signature | keyword |
| azure.activitylogs.result_type | Result type | keyword |
| azure.correlation_id | Correlation ID | keyword |
| azure.resource.authorization_rule | Authorization rule | keyword |
| azure.resource.group | Resource group | keyword |
| azure.resource.id | Resource ID | keyword |
| azure.resource.name | Name | keyword |
| azure.resource.namespace | Resource type/namespace | keyword |
| azure.resource.provider | Resource type/namespace | keyword |
| azure.subscription_id | Azure subscription ID | keyword |
| azure.tenant_id | tenant ID | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| destination.address | Destination network address. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.name | User-defined description of a location. | keyword |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination. | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. | keyword |
| error.message | Error message. | text |
| event.action | The action captured by the event. | keyword |
| event.category | Event category. The second categorization field in the hierarchy. | keyword |
| event.created | Time when the event was first read by an agent or by your pipeline. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| event.kind | The kind of the event. The highest categorization field in the hierarchy. | keyword |
| event.type | Event type. The third categorization field in the hierarchy. | keyword |
| file.mime_type | Media type of file, document, or arrangement of bytes. | keyword |
| file.size | File size in bytes. | long |
| geo.city_name | City name. | keyword |
| geo.continent_name | Name of the continent. | keyword |
| geo.country_iso_code | Country ISO code. | keyword |
| geo.country_name | Country name. | keyword |
| geo.location | Longitude and latitude. | geo_point |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| log.level | Log level of the log event. | keyword |
| message | Message. | text |
| network.community_id | A hash of source and destination IPs and ports. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names seen on your event. | keyword |
| source.address | Source network address. | keyword |
| source.as.number | Unique number allocated to the autonomous system. | long |
| source.as.organization.name | Organization name. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source. | ip |
| source.port | Port of the source. | long |
| user.domain | Domain of the user. | keyword |
| user.full_name | Full name of the user. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |


An example event for `platformlogs` looks as following:

```$json
{
    "_index": ".ds-logs-azure.platformlogs-default-000001",
    "_type": "_doc",
    "_id": "BHSwg3UBWgbgrXIaDOF-",
    "_score": null,
    "_source": {
        "agent": {
            "hostname": "DESKTOP-RFOOE09",
            "name": "DESKTOP-RFOOE09",
            "id": "c1118415-bcb7-4cf9-b64d-a6c6e8ebcfac",
            "type": "filebeat",
            "ephemeral_id": "d3c4d56c-e7c7-489e-9d25-683452d16ec9",
            "version": "7.10.0"
        },
        "elastic_agent": {
            "id": "02f4e39d-8a1b-4506-a531-b45d0f492ee7",
            "version": "7.10.0",
            "snapshot": false
        },
        "azure-eventhub": {
            "sequence_number": 15,
            "consumer_group": "$Default",
            "offset": 4294976088,
            "eventhub": "insights-logs-operationallogs",
            "enqueued_time": "2020-11-05T14:08:28.137Z"
        },
        "tags": [
            "forwarded"
        ],
        "cloud": {
            "provider": "azure",
            "region": "West Europe"
        },
        "input": {
            "type": "azure-eventhub"
        },
        "@timestamp": "2020-11-05T14:07:32.000Z",
        "ecs": {
            "version": "1.5.0"
        },
        "data_stream": {
            "namespace": "default",
            "type": "logs",
            "dataset": "azure.platformlogs"
        },
        "host": {
            "name": "DESKTOP-RFOOE09"
        },
        "event": {
            "ingested": "2020-11-01T12:02:34.237205200Z",
            "kind": "event",
            "action": "Retreive Namespace",
            "dataset": "azure.platformlogs",
            "outcome": "succeeded"
        },
        "azure": {
            "subscription_id": "7657426D-C4C3-44AC-88A2-3B2CD59E6DBA",
            "platformlogs": {
                "Status": "Succeeded",
                "SubscriptionId": "7657426d-c4c3-44ac-88a2-3b2cd59e6dba",
                "Caller": "Portal",
                "ActivityId": "5890c6fc-fc6b-47cd-971a-2366a1641d99",
                "EventTimeString": "11/5/2020 2:07:32 PM +00:00",
                "Environment": "PROD",
                "category": "OperationalLogs",
                "event_category": "Administrative",
                "ScaleUnit": "PROD-AM3-AZ501",
                "properties": {
                    "SubscriptionId": "7657426d-c4c3-44ac-88a2-3b2cd59e6dba",
                    "TrackingId": "5890c6fc-fc6b-47cd-971a-2366a1641d99_M8CH3_M8CH3_G8S3",
                    "Namespace": "obstesteventhubs",
                    "Via": "https://obstesteventhubs.servicebus.windows.net/$Resources/eventhubs?api-version=2017-04\u0026$skip=0\u0026$top=100"
                }
            },
            "resource": {
                "provider": "MICROSOFT.EVENTHUB/NAMESPACES",
                "name": "OBSTESTEVENTHUBS",
                "id": "/SUBSCRIPTIONS/7657426D-C4C3-44AC-88A2-3B2CD59E6DBA/RESOURCEGROUPS/OBS-TEST/PROVIDERS/MICROSOFT.EVENTHUB/NAMESPACES/OBSTESTEVENTHUBS",
                "group": "OBS-TEST"
            }
        }
    }
}
```

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
| azure.platformlogs.operation_name | Operation name | keyword |
| azure.platformlogs.properties.* | Properties | object |
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
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| destination.address | Destination network address. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.name | User-defined description of a location. | keyword |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination. | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. | keyword |
| error.message | Error message. | text |
| event.action | The action captured by the event. | keyword |
| event.category | Event category. The second categorization field in the hierarchy. | keyword |
| event.created | Time when the event was first read by an agent or by your pipeline. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| event.kind | The kind of the event. The highest categorization field in the hierarchy. | keyword |
| event.type | Event type. The third categorization field in the hierarchy. | keyword |
| file.mime_type | Media type of file, document, or arrangement of bytes. | keyword |
| file.size | File size in bytes. | long |
| geo.city_name | City name. | keyword |
| geo.continent_name | Name of the continent. | keyword |
| geo.country_iso_code | Country ISO code. | keyword |
| geo.country_name | Country name. | keyword |
| geo.location | Longitude and latitude. | geo_point |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| log.level | Log level of the log event. | keyword |
| message | Message. | text |
| network.community_id | A hash of source and destination IPs and ports. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names seen on your event. | keyword |
| source.address | Source network address. | keyword |
| source.as.number | Unique number allocated to the autonomous system. | long |
| source.as.organization.name | Organization name. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source. | ip |
| source.port | Port of the source. | long |
| user.domain | Domain of the user. | keyword |
| user.full_name | Full name of the user. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |


An example event for `auditlogs` looks as following:

```$json
{
    "_index": ".ds-logs-azure.auditlogs-default-000001",
    "_type": "_doc",
    "_id": "bQlEe3UBm_qs2Y3aNZPq",
    "_score": null,
    "_source": {
        "log": {
            "level": "Information"
        },
        "azure-eventhub": {
            "sequence_number": 643,
            "consumer_group": "$Default",
            "offset": 107374182400,
            "eventhub": "insights-auditlogs-logs",
            "enqueued_time": "2020-11-02T08:59:38.905Z"
        },
        "tags": [
            "forwarded"
        ],
        "cloud": {
            "provider": "azure"
        },
        "input": {
            "type": "azure-eventhub"
        },
        "@timestamp": "2020-11-02T08:51:36.997Z",
        "ecs": {
            "version": "1.5.0"
        },
        "data_stream": {
            "namespace": "default",
            "type": "logs",
            "dataset": "azure.auditlogs"
        },
        "event": {
            "duration": "0",
            "ingested": "2020-10-30T20:47:48.123859400Z",
            "kind": "event",
            "action": "MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE",
            "dataset": "azure.auditlogs",
            "outcome": "success"
        },
        "azure.correlation_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
        "azure.resource.id": "/tenants/8a4de8b5-095c-47d0-a96f-a75130c61d53/providers/Microsoft.aadiam",
        "azure.resource.provider": "Microsoft.aadiam",
        "azure.tenant_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
        "azure.auditlogs.category": "AuditLogs",
        "azure.auditlogs.identity": "Device Registration Service",
        "azure.auditlogs.operation_name": "Update device",
        "azure.auditlogs.operation_version": "1.0",
        "azure.auditlogs.properties.activity_datetime": "2019-10-18T15:30:51.0273716+00:00",
        "azure.auditlogs.properties.activity_display_name": "Update device",
        "azure.auditlogs.properties.category": "Device",
        "azure.auditlogs.properties.correlation_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
        "azure.auditlogs.properties.id": "Directory_ESQ",
        "azure.auditlogs.properties.initiated_by.app.appId": null,
        "azure.auditlogs.properties.initiated_by.app.displayName": "Device Registration Service",
        "azure.auditlogs.properties.initiated_by.app.servicePrincipalId": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
        "azure.auditlogs.properties.initiated_by.app.servicePrincipalName": null,
        "azure.auditlogs.properties.logged_by_service": "Core Directory",
        "azure.auditlogs.properties.operation_type": "Update",
        "azure.auditlogs.properties.result_reason": "",
        "azure.auditlogs.properties.target_resources.0.display_name": "LAPTOP-12",
        "azure.auditlogs.properties.target_resources.0.id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
        "azure.auditlogs.properties.target_resources.0.modified_properties.0.display_name": "Included Updated Properties",
        "azure.auditlogs.properties.target_resources.0.modified_properties.0.new_value": "\"\"",
        "azure.auditlogs.properties.target_resources.0.modified_properties.0.old_value": null,
        "azure.auditlogs.properties.target_resources.0.type": "Device",
        "azure.auditlogs.result_signature": "None"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.auditlogs.category | The category of the operation.  Currently, Audit is the only supported value. | keyword |
| azure.auditlogs.identity | Identity | keyword |
| azure.auditlogs.operation_name | The operation name | keyword |
| azure.auditlogs.operation_version | The operation version | keyword |
| azure.auditlogs.properties.activity_datetime | Activity timestamp | date |
| azure.auditlogs.properties.activity_display_name | Activity display name | keyword |
| azure.auditlogs.properties.category | category | keyword |
| azure.auditlogs.properties.correlation_id | Correlation ID | keyword |
| azure.auditlogs.properties.id | ID | keyword |
| azure.auditlogs.properties.initiated_by.app.appId | App ID | keyword |
| azure.auditlogs.properties.initiated_by.app.displayName | Display name | keyword |
| azure.auditlogs.properties.initiated_by.app.servicePrincipalId | Service principal ID | keyword |
| azure.auditlogs.properties.initiated_by.app.servicePrincipalName | Service principal name | keyword |
| azure.auditlogs.properties.initiated_by.user.displayName | Display name | keyword |
| azure.auditlogs.properties.initiated_by.user.id | ID | keyword |
| azure.auditlogs.properties.initiated_by.user.ipAddress | ip Address | keyword |
| azure.auditlogs.properties.initiated_by.user.userPrincipalName | User principal name | keyword |
| azure.auditlogs.properties.logged_by_service | Logged by service | keyword |
| azure.auditlogs.properties.operation_type | Operation type | keyword |
| azure.auditlogs.properties.result | Log result | keyword |
| azure.auditlogs.properties.result_reason | Reason for the log result | keyword |
| azure.auditlogs.properties.target_resources.*.display_name | Display name | keyword |
| azure.auditlogs.properties.target_resources.*.id | ID | keyword |
| azure.auditlogs.properties.target_resources.*.ip_address | ip Address | keyword |
| azure.auditlogs.properties.target_resources.*.modified_properties.*.display_name | Display value | keyword |
| azure.auditlogs.properties.target_resources.*.modified_properties.*.new_value | New value | keyword |
| azure.auditlogs.properties.target_resources.*.modified_properties.*.old_value | Old value | keyword |
| azure.auditlogs.properties.target_resources.*.type | Type | keyword |
| azure.auditlogs.properties.target_resources.*.user_principal_name | User principal name | keyword |
| azure.auditlogs.result_signature | Result signature | keyword |
| azure.auditlogs.tenant_id | Tenant ID | keyword |
| azure.correlation_id | Correlation ID | keyword |
| azure.resource.authorization_rule | Authorization rule | keyword |
| azure.resource.group | Resource group | keyword |
| azure.resource.id | Resource ID | keyword |
| azure.resource.name | Name | keyword |
| azure.resource.namespace | Resource type/namespace | keyword |
| azure.resource.provider | Resource type/namespace | keyword |
| azure.subscription_id | Azure subscription ID | keyword |
| azure.tenant_id | tenant ID | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| destination.address | Destination network address. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.name | User-defined description of a location. | keyword |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination. | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. | keyword |
| error.message | Error message. | text |
| event.action | The action captured by the event. | keyword |
| event.category | Event category. The second categorization field in the hierarchy. | keyword |
| event.created | Time when the event was first read by an agent or by your pipeline. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| event.kind | The kind of the event. The highest categorization field in the hierarchy. | keyword |
| event.type | Event type. The third categorization field in the hierarchy. | keyword |
| file.mime_type | Media type of file, document, or arrangement of bytes. | keyword |
| file.size | File size in bytes. | long |
| geo.city_name | City name. | keyword |
| geo.continent_name | Name of the continent. | keyword |
| geo.country_iso_code | Country ISO code. | keyword |
| geo.country_name | Country name. | keyword |
| geo.location | Longitude and latitude. | geo_point |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| log.level | Log level of the log event. | keyword |
| message | Message. | text |
| network.community_id | A hash of source and destination IPs and ports. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names seen on your event. | keyword |
| source.address | Source network address. | keyword |
| source.as.number | Unique number allocated to the autonomous system. | long |
| source.as.organization.name | Organization name. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source. | ip |
| source.port | Port of the source. | long |
| user.domain | Domain of the user. | keyword |
| user.full_name | Full name of the user. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |


An example event for `signinlogs` looks as following:

```$json
{
    "_index": ".ds-logs-azure.signinlogs-default-000001",
    "_type": "_doc",
    "_id": "bQlEe3UBm_qs2Y3aNZPq",
    "_score": null,
    "_source": {
        "log": {
            "level": "Information"
        },
        "azure-eventhub": {
            "sequence_number": 643,
            "consumer_group": "$Default",
            "offset": 107374182400,
            "eventhub": "insights-signinlogs-logs",
            "enqueued_time": "2020-11-02T08:59:38.905Z"
        },
        "tags": [
            "forwarded"
        ],
        "cloud": {
            "provider": "azure"
        },
        "input": {
            "type": "azure-eventhub"
        },
        "@timestamp": "2020-11-02T08:51:36.997Z",
        "ecs": {
            "version": "1.5.0"
        },
        "data_stream": {
            "namespace": "default",
            "type": "logs",
            "dataset": "azure.auditlogs"
        },
        "azure.correlation_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
        "azure.resource.id": "/tenants/8a4de8b5-095c-47d0-a96f-a75130c61d53/providers/Microsoft.aadiam",
        "azure.resource.provider": "Microsoft.aadiam",
        "azure.signinlogs.category": "SignInLogs",
        "azure.signinlogs.identity": "Test LTest",
        "azure.signinlogs.operation_name": "Sign-in activity",
        "azure.signinlogs.operation_version": "1.0",
        "azure.signinlogs.properties.app_display_name": "Office 365",
        "azure.signinlogs.properties.app_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
        "azure.signinlogs.properties.client_app_used": "Browser",
        "azure.signinlogs.properties.conditional_access_status": "notApplied",
        "azure.signinlogs.properties.correlation_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
        "azure.signinlogs.properties.created_at": "2019-10-18T04:45:48.0729893-05:00",
        "azure.signinlogs.properties.device_detail.browser": "Chrome 77.0.3865",
        "azure.signinlogs.properties.device_detail.device_id": "",
        "azure.signinlogs.properties.device_detail.operating_system": "MacOs",
        "azure.signinlogs.properties.id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
        "azure.signinlogs.properties.ip_address": "81.171.241.231",
        "azure.signinlogs.properties.is_interactive": false,
        "azure.signinlogs.properties.original_request_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
        "azure.signinlogs.properties.processing_time_ms": 239,
        "azure.signinlogs.properties.risk_detail": "none",
        "azure.signinlogs.properties.risk_level_aggregated": "none",
        "azure.signinlogs.properties.risk_level_during_signin": "none",
        "azure.signinlogs.properties.risk_state": "none",
        "azure.signinlogs.properties.service_principal_id": "",
        "azure.signinlogs.properties.status.error_code": 50140,
        "azure.signinlogs.properties.token_issuer_name": "",
        "azure.signinlogs.properties.token_issuer_type": "AzureAD",
        "azure.signinlogs.properties.user_display_name": "Test LTest",
        "azure.signinlogs.properties.user_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
        "azure.signinlogs.properties.user_principal_name": "test@elastic.co",
        "azure.signinlogs.result_description": "This error occurred due to 'Keep me signed in' interrupt when the user was signing-in.",
        "azure.signinlogs.result_signature": "None",
        "azure.signinlogs.result_type": "50140",
        "azure.tenant_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
        "cloud.provider": "azure",
        "event.action": "Sign-in activity",
        "event.category": [
            "authentication"
        ]
    }
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
| azure.signinlogs.category | Category | keyword |
| azure.signinlogs.identity | Identity | keyword |
| azure.signinlogs.operation_name | The operation name | keyword |
| azure.signinlogs.operation_version | The operation version | keyword |
| azure.signinlogs.properties.app_display_name | App display name | keyword |
| azure.signinlogs.properties.app_id | App ID | keyword |
| azure.signinlogs.properties.client_app_used | Client app used | keyword |
| azure.signinlogs.properties.conditional_access_status | Conditional access status | keyword |
| azure.signinlogs.properties.correlation_id | Correlation ID | keyword |
| azure.signinlogs.properties.created_at | Created date time | date |
| azure.signinlogs.properties.device_detail.browser | Browser | keyword |
| azure.signinlogs.properties.device_detail.device_id | Device ID | keyword |
| azure.signinlogs.properties.device_detail.display_name | Display name | keyword |
| azure.signinlogs.properties.device_detail.operating_system | Operating system | keyword |
| azure.signinlogs.properties.device_detail.trust_type | Trust type | keyword |
| azure.signinlogs.properties.id | ID | keyword |
| azure.signinlogs.properties.ip_address | Ip address | keyword |
| azure.signinlogs.properties.is_interactive | Is interactive | boolean |
| azure.signinlogs.properties.original_request_id | Original request ID | keyword |
| azure.signinlogs.properties.processing_time_ms | Processing time in milliseconds | float |
| azure.signinlogs.properties.resource_display_name | Resource display name | keyword |
| azure.signinlogs.properties.risk_detail | Risk detail | keyword |
| azure.signinlogs.properties.risk_level_aggregated | Risk level aggregated | keyword |
| azure.signinlogs.properties.risk_level_during_signin | Risk level during signIn | keyword |
| azure.signinlogs.properties.risk_state | Risk state | keyword |
| azure.signinlogs.properties.service_principal_id | Status | keyword |
| azure.signinlogs.properties.status.error_code | Error code | long |
| azure.signinlogs.properties.token_issuer_name | Token issuer name | keyword |
| azure.signinlogs.properties.token_issuer_type | Token issuer type | keyword |
| azure.signinlogs.properties.user_display_name | User display name | keyword |
| azure.signinlogs.properties.user_id | User ID | keyword |
| azure.signinlogs.properties.user_principal_name | User principal name | keyword |
| azure.signinlogs.result_description | Result description | keyword |
| azure.signinlogs.result_signature | Result signature | keyword |
| azure.signinlogs.result_type | Result type | keyword |
| azure.signinlogs.tenant_id | Tenant ID | keyword |
| azure.subscription_id | Azure subscription ID | keyword |
| azure.tenant_id | tenant ID | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| destination.address | Destination network address. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.name | User-defined description of a location. | keyword |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination. | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. | keyword |
| error.message | Error message. | text |
| event.action | The action captured by the event. | keyword |
| event.category | Event category. The second categorization field in the hierarchy. | keyword |
| event.created | Time when the event was first read by an agent or by your pipeline. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| event.kind | The kind of the event. The highest categorization field in the hierarchy. | keyword |
| event.type | Event type. The third categorization field in the hierarchy. | keyword |
| file.mime_type | Media type of file, document, or arrangement of bytes. | keyword |
| file.size | File size in bytes. | long |
| geo.city_name | City name. | keyword |
| geo.continent_name | Name of the continent. | keyword |
| geo.country_iso_code | Country ISO code. | keyword |
| geo.country_name | Country name. | keyword |
| geo.location | Longitude and latitude. | geo_point |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| log.level | Log level of the log event. | keyword |
| message | Message. | text |
| network.community_id | A hash of source and destination IPs and ports. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names seen on your event. | keyword |
| source.address | Source network address. | keyword |
| source.as.number | Unique number allocated to the autonomous system. | long |
| source.as.organization.name | Organization name. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source. | ip |
| source.port | Port of the source. | long |
| user.domain | Domain of the user. | keyword |
| user.full_name | Full name of the user. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |







