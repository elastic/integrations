# Azure Application Insights Integration

The azure logs integration retrieves different types of log data from Azure.
There are several requirements before using the module since the logs will actually be read from azure event hubs.

   - the logs have to be exported first to the event hub https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-create-kafka-enabled
   - to export activity logs to event hubs users can follow the steps here https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-export
   - to export audit and sign-in logs to event hubs users can follow the steps here https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/tutorial-azure-monitor-stream-logs-to-event-hub

The module contains the following filesets:

### app_insights
Will retrieve azure activity logs. Control-plane events on Azure Resource Manager resources. Activity logs provide insight into the operations that were performed on resources in your subscription.

### app_state
Will retrieve azure platform logs. Platform logs provide detailed diagnostic and auditing information for Azure resources and the Azure platform they depend on.

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


An example event for `app_insights` looks as following:

```$json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "agent": {
        "hostname": "host.example.com",
        "name": "host.example.com"
    },
    "container": {
        "id": "cc78e58acfda4501105dc4de8e3ae218f2da616213e6e3af168c40103829302a",
        "image": {
            "name": "metricbeat_elasticsearch"
        },
        "name": "metricbeat_elasticsearch_1_df866b3a7b3d",
        "runtime": "docker"
    },
    "docker": {
        "container": {
            "command": "/usr/local/bin/docker-entrypoint.sh eswrapper",
            "created": "2019-02-25T10:18:10.000Z",
            "ip_addresses": [
                "172.23.0.2"
            ],
            "labels": {
                "com_docker_compose_config-hash": "e3e0a2c6e5d1afb741bc8b1ecb09cda0395886b7a3e5084a9fd110be46d70f78",
                "com_docker_compose_container-number": "1",
                "com_docker_compose_oneoff": "False",
                "com_docker_compose_project": "metricbeat",
                "com_docker_compose_service": "elasticsearch",
                "com_docker_compose_slug": "df866b3a7b3d50c0802350cbe58ee5b34fa32b7f6ba7fe9e48cde2c12dd0201d",
                "com_docker_compose_version": "1.23.1",
                "license": "Elastic License",
                "org_label-schema_build-date": "20181006",
                "org_label-schema_license": "GPLv2",
                "org_label-schema_name": "elasticsearch",
                "org_label-schema_schema-version": "1.0",
                "org_label-schema_url": "https://www.elastic.co/products/elasticsearch",
                "org_label-schema_vcs-url": "https://github.com/elastic/elasticsearch-docker",
                "org_label-schema_vendor": "Elastic",
                "org_label-schema_version": "6.5.1"
            },
            "size": {
                "root_fs": 0,
                "rw": 0
            },
            "status": "Up 7 minutes (healthy)"
        }
    },
    "event": {
        "dataset": "docker.container",
        "duration": 115000,
        "module": "docker"
    },
    "metricset": {
        "name": "container"
    },
    "service": {
        "address": "/var/run/docker.sock",
        "type": "docker"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.name | Container name. | keyword |
| container.runtime | Container runtime. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| docker.container.labels.* | Container labels | object |
| docker.cpu.core.*.norm.pct | Percentage of CPU time in this core, normalized by the number of CPU cores. | object |
| docker.cpu.core.*.pct | Percentage of CPU time in this core. | object |
| docker.cpu.core.*.ticks | Number of CPU ticks in this core. | object |
| docker.cpu.kernel.norm.pct | Percentage of time in kernel space normalized by the number of CPU cores. | scaled_float |
| docker.cpu.kernel.pct | Percentage of time in kernel space. | scaled_float |
| docker.cpu.kernel.ticks | CPU ticks in kernel space. | long |
| docker.cpu.system.norm.pct | Percentage of total CPU time in the system normalized by the number of CPU cores. | scaled_float |
| docker.cpu.system.pct | Percentage of total CPU time in the system. | scaled_float |
| docker.cpu.system.ticks | CPU system ticks. | long |
| docker.cpu.total.norm.pct | Total CPU usage normalized by the number of CPU cores. | scaled_float |
| docker.cpu.total.pct | Total CPU usage. | scaled_float |
| docker.cpu.user.norm.pct | Percentage of time in user space normalized by the number of CPU cores. | scaled_float |
| docker.cpu.user.pct | Percentage of time in user space. | scaled_float |
| docker.cpu.user.ticks | CPU ticks in user space. | long |
| ecs.version | ECS version | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.ip | Host ip address. | ip |
| host.mac | Host mac address. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.full | Operating system name, including the version or code name. | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. | keyword |
| service.address | Service address | keyword |
| service.type | Service type | keyword |








