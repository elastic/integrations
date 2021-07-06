## Logs
The azure logs integration retrieves different types of log data from Azure.
There are several requirements before using the integration since the logs will actually be read from azure event hubs.

   - the logs have to be exported first to the event hub https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-create-kafka-enabled
   - to export activity logs to event hubs users can follow the steps here https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-export
   - to export audit and sign-in logs to event hubs users can follow the steps here https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/tutorial-azure-monitor-stream-logs-to-event-hub



Activity logs provide insight into the operations that were performed on resources in your subscription.


### activitylogs

This is the `activitylogs` dataset of the Azure Logs package. It will collect any activity events that have been streamed through an azure event hub.

An example event for `activitylogs` looks as following:

```json
{
    "log": {
        "level": "Information"
    },
    "cloud": {
        "provider": "azure"
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
            "result_signature": "Succeeded."
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
| azure.activitylogs.properties | Event properties | flattened |
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
| client.ip | IP address of the client. | ip |
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
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| event.kind | The kind of the event. The highest categorization field in the hierarchy. | keyword |
| event.module | Event module | constant_keyword |
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
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Domain of the user. | keyword |
| user.full_name | Full name of the user. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
