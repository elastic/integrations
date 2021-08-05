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
    "azure-eventhub": {
        "sequence_number": 80,
        "consumer_group": "$Default",
        "offset": 62080,
        "eventhub": "insights-logs-applicationconsole",
        "enqueued_time": "2021-08-03T15:08:14.477Z"
    },
    "tags": [
        "azure-springcloudlogs"
    ],
    "geo": {
        "name": "westeurope"
    },
    "cloud": {
        "provider": "azure"
    },
    "input": {
        "type": "azure-eventhub"
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
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "4.19.128-microsoft-standard",
            "codename": "Core",
            "name": "CentOS Linux",
            "family": "redhat",
            "type": "linux",
            "version": "7 (Core)",
            "platform": "centos"
        },
        "containerized": true,
        "ip": [
            "172.29.0.7"
        ],
        "name": "docker-fleet-agent",
        "id": "78315c3233258f2dcd540ed749ab1701",
        "mac": [
            "02:42:ac:1d:00:07"
        ],
        "architecture": "x86_64"
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
| azure.springcloudlogs.Cloud | Cloud | keyword |
| azure.springcloudlogs.Environment | Environment | keyword |
| azure.springcloudlogs.EventTimeString | EventTimeString | keyword |
| azure.springcloudlogs.category | Category | keyword |
| azure.springcloudlogs.ccpNamespace | ccpNamespace | keyword |
| azure.springcloudlogs.event_category | Event Category | keyword |
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
| azure.springcloudlogs.result_signature | Result signature | keyword |
| azure.springcloudlogs.result_type | Result type | keyword |
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
| destination | Destination fields capture details about the receiver of a network exchange/packet. These fields are populated from a network event, packet, or other event containing details of a network transaction. Destination fields are usually populated in conjunction with source fields. The source and destination fields are considered the baseline and should always be filled if an event contains source and destination details from a network transaction. If the event also contains identification of the client and server roles, then the client and server fields should also be populated. | group |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |
| event | The event fields are used for context information about the log or metric event itself. A log is defined as an event containing details of something that happened. Log events must include the time at which the thing happened. Examples of log events include a process starting on a host, a network packet being sent from a source to a destination, or a network connection between a client and a server being initiated or closed. A metric is defined as an event containing one or more numerical measurements and the time at which the measurement was taken. Examples of metric events include memory pressure measured on a host and device temperature. See the `event.kind` definition in this section for additional details about metric and state events. | group |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| geo | Geo fields can carry data about a specific location related to an event. This geolocation information can be derived from techniques such as Geo IP, or be user-supplied. | group |
| host | A host is defined as a general computing instance. ECS host.\* fields should be populated with details about the host on which the event happened, or from which the measurement was taken. Host types include hardware, virtual machines, Docker containers, and Kubernetes nodes. | group |
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
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
| related | This field set is meant to facilitate pivoting around a piece of data. Some pieces of information can be seen in many places in an ECS event. To facilitate searching for them, store an array of all seen values to their corresponding field in `related.`. A concrete example is IP addresses, which can be under host, observer, source, destination, client, server, and network.forwarded_ip. If you append all IPs to `related.ip`, you can then search for a given IP trivially, no matter where it appeared, by querying `related.ip:192.0.2.15`. | group |
| service.address | Service address | keyword |
| source | Source fields capture details about the sender of a network exchange/packet. These fields are populated from a network event, packet, or other event containing details of a network transaction. Source fields are usually populated in conjunction with destination fields. The source and destination fields are considered the baseline and should always be filled if an event contains source and destination details from a network transaction. If the event also contains identification of the client and server roles, then the client and server fields should also be populated. | group |
| tags | List of keywords used to tag each event. | keyword |
| user | The user fields describe information about the user that is relevant to the event. Fields can have one entry or multiple entries. If a user has more than one id, provide an array that includes all of them. | group |
