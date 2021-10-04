# CockroachDB Integration

This integration collects metrics from CockroachDB. It includes the
following datasets for receiving logs:

- `status` datastream: consists of status metrics

## Compatibility

The CockroachDB integration is compatible with any CockroachDB version
exposing metrics in Prometheus format.

### status

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| cockroachdb.confidence_level | Confidence level determined by ThreatCloud. | integer |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
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
| service.address | Service address | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


An example event for `status` looks as following:

```json
{
    "agent": {
        "hostname": "docker-fleet-agent",
        "name": "docker-fleet-agent",
        "id": "6493df64-791a-4b55-b2e9-c5b1dd347fe7",
        "type": "metricbeat",
        "ephemeral_id": "833a8afe-815e-4ed5-b7a1-bd0e30d626ed",
        "version": "7.14.0"
    },
    "elastic_agent": {
        "id": "6493df64-791a-4b55-b2e9-c5b1dd347fe7",
        "version": "7.14.0",
        "snapshot": true
    },
    "cloud": {
        "provider": "azure",
        "region": "westeurope"
    },
    "@timestamp": "2021-07-26T08:02:00.000Z",
    "ecs": {
        "version": "1.10.0"
    },
    "service": {
        "type": "azure"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "azure.storage_account"
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
            "172.20.0.7"
        ],
        "name": "docker-fleet-agent",
        "id": "d4845dae196bc2de62b7b208c215d5bc",
        "mac": [
            "02:42:ac:14:00:07"
        ],
        "architecture": "x86_64"
    },
    "metricset": {
        "period": 300000,
        "name": "storage"
    },
    "event": {
        "duration": 4780565600,
        "agent_id_status": "verified",
        "ingested": "2021-07-26T10:02:22.993256Z",
        "module": "azure",
        "dataset": "azure.storage_account"
    },
    "azure": {
        "subscription_id": "70bd6e77-4b1e-4835-8896-db77b8eef364",
        "timegrain": "PT1H",
        "resource": {
            "name": "blobtestobs",
            "id": "/subscriptions/70bd6e77-4b1e-4835-8896-db77b8eef364/resourceGroups/obs-infrastructure/providers/Microsoft.Storage/storageAccounts/blobtestobs",
            "type": "Microsoft.Storage/storageAccounts",
            "tags": {
                "test_ye": "valuw1.value1",
                "test": "value.value"
            },
            "group": "obs-infrastructure"
        },
        "namespace": "Microsoft.Storage/storageAccounts",
        "storage_account": {
            "used_capacity": {
                "avg": 6976
            }
        }
    }
}
```


