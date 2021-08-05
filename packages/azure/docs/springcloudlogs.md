## Logs

The azure logs integration retrieves different types of log data from Azure.
There are several requirements before using the integration since the logs will actually be read from azure event hubs.

   * the logs have to be exported first to the event hub https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-create-kafka-enabled
   * to export activity logs to event hubs users can follow the steps here https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-export
   * to export audit and sign-in logs to event hubs users can follow the steps here https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/tutorial-azure-monitor-stream-logs-to-event-hub


Azure Spring Cloud logs provide system and application information for Azure Spring Cloud resources.

### springcloudlogs

This is the `springcloudlogs` data stream of the Azure Logs package. It will collect any Spring Cloud logs that have been streamed through an azure event hub.

An example event for `springcloudlogs` looks as following:

```json
{
    "agent": {
        "hostname": "docker-fleet-agent",
        "name": "docker-fleet-agent",
        "id": "ef999bb2-fe83-4ffa-aa0c-0b54b7598df4",
        "type": "filebeat",
        "ephemeral_id": "49d0a57c-119c-4a01-878c-d9b06fc81f65",
        "version": "7.14.0"
    },
    "log": {
        "level": "Informational"
    },
    "elastic_agent": {
        "id": "ef999bb2-fe83-4ffa-aa0c-0b54b7598df4",
        "version": "7.14.0",
        "snapshot": true
    },
    "message": "2021-08-03 15:07:03.354  INFO [helloapp,,,] 1 --- [trap-executor-0] c.n.d.s.r.aws.ConfigClusterResolver      : Resolving eureka endpoints via configuration",
    "tags": [
        "azure-springcloudlogs"
    ],
    "geo": {
        "name": "westeurope"
    },
    "cloud": {
        "provider": "azure"
    },
    "@timestamp": "2021-08-03T15:07:03.354Z",
    "ecs": {
        "version": "1.10.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "azure.springcloudlogs"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2021-08-03T15:15:14.386889100Z",
        "kind": "event",
        "action": "Microsoft.AppPlatform/Spring/logs",
        "dataset": "azure.springcloudlogs"
    },
    "azure": {
        "subscription_id": "0E073EC1-C22F-4488-ADDE-DA35ED609CCD",
        "springcloudlogs": {
            "log_format": "RAW",
            "operation_name": "Microsoft.AppPlatform/Spring/logs",
            "category": "ApplicationConsole",
            "event_category": "Administrative",
            "logtag": "F",
            "properties": {
                "app_name": "helloapp",
                "instance_name": "helloapp-default-8-56df6b7f56-4vr94",
                "stream": "stdout",
                "service_name": "obssprincloud",
                "service_id": "99070c7524f14eaf970bbdf35f357772"
            }
        },
        "resource": {
            "provider": "MICROSOFT.APPPLATFORM/SPRING",
            "name": "OBSSPRINCLOUD",
            "id": "/SUBSCRIPTIONS/0E073EC1-C22F-4488-ADDE-DA35ED609CCD/RESOURCEGROUPS/TESTM/PROVIDERS/MICROSOFT.APPPLATFORM/SPRING/OBSSPRINCLOUD",
            "group": "TESTM"
        }
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
| geo.name | User-defined description of a location. | keyword |
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
