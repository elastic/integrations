# Microsoft Entra ID Entity Analytics

This integration retrieves users, with group memberships, from Microsoft Entra ID
(formerly Azure Active Directory).

## Configuration

The necessary API permissions need to be granted in Microsoft Entra in order for the
integration to function properly:

| Permission           | Type        |
|----------------------|-------------|
| GroupMember.Read.All | Application |
| User.Read.All        | Application |

For a full guide on how to set up the necessary App Registration, permission
granting, and secret configuration, follow this [guide](https://learn.microsoft.com/en-us/graph/auth-v2-service).

## Usage

The integration periodically contacts Microsoft Entra ID using the Graph API,
retrieving updates for users and groups, updates its internal cache of user
metadata and group membership information, and ships updated user metadata to
Elasticsearch.

Fetching and shipping updates occurs in one of two processes: **full synchronizations**
and **incremental updates**. Full synchronizations will send the entire list of
users in state, along with write markers to indicate the start and end of the
synchronization event. Incremental updates will only send data for changed users
during that event. Changes on a user can come in many forms, whether it be a
change to the user's metadata, a user was added or deleted, or group membership
was changed (either direct or transitive). By default, full synchronizations
occur every 24 hours and incremental updates occur every hour. These intervals
may be customized to suit your use case.

## Sample Events

An example event for `entity` looks as following:

```json
{
    "@timestamp": "2023-08-15T14:38:54.461Z",
    "agent": {
        "ephemeral_id": "d6f9f501-2f57-475f-ac8a-0f07a280ab47",
        "id": "a5d370e8-ae36-45f7-adbd-f22b984b979d",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.0"
    },
    "data_stream": {
        "dataset": "entityanalytics_entra_id.entity",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.9.0"
    },
    "elastic_agent": {
        "id": "a5d370e8-ae36-45f7-adbd-f22b984b979d",
        "snapshot": true,
        "version": "8.10.0"
    },
    "event": {
        "action": "started",
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "entityanalytics_entra_id.entity",
        "ingested": "2023-08-15T14:38:57Z",
        "start": "2023-08-15T14:38:54.461Z",
        "type": [
            "user",
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "e99a2f1240444f1d9b0988489b67037d",
        "ip": [
            "192.168.112.7"
        ],
        "mac": [
            "02-42-C0-A8-70-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.47-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "entity-analytics"
    },
    "labels": {
        "identity_source": "entity-analytics-entityanalytics_entra_id.entity-91c18afb-5a41-4079-90d1-3bd684fb38a9"
    }
}
```

The "write markers" bounding a full synchronization:

```json
{
  "input": {
    "type": "entity-analytics"
  },
  "@timestamp": "2023-03-22T14:34:37.693Z",
  "ecs": {
    "version": "8.7.0"
  },
  "data_stream": {
    "namespace": "ep",
    "type": "logs",
    "dataset": "entityanalytics_entra_id.entity"
  },
  "event": {
    "agent_id_status": "verified",
    "ingested": "2023-03-22T14:34:41Z",
    "start": "2023-03-22T14:34:37.693Z",
    "action": "started",
    "category": [
      "iam"
    ],
    "type": [
      "user",
      "info"
    ],
    "dataset": "entityanalytics_entra_id.entity"
  },
  "labels": {
    "identity_source": "entity-analytics-entityanalytics_entra_id.entity-d59eafe1-0583-4d42-b298-2bd30ef0b3b7"
  }
}
```

```json
{
  "input": {
    "type": "entity-analytics"
  },
  "@timestamp": "2023-03-22T14:34:40.684Z",
  "ecs": {
    "version": "8.7.0"
  },
  "data_stream": {
    "namespace": "ep",
    "type": "logs",
    "dataset": "entityanalytics_entra_id.entity"
  },
  "event": {
    "agent_id_status": "verified",
    "ingested": "2023-03-22T14:34:41Z",
    "action": "completed",
    "end": "2023-03-22T14:34:40.684Z",
    "category": [
      "iam"
    ],
    "type": [
      "user",
      "info"
    ],
    "dataset": "entityanalytics_entra_id.entity"
  },
  "labels": {
    "identity_source": "entity-analytics-entityanalytics_entra_id.entity-d59eafe1-0583-4d42-b298-2bd30ef0b3b7"
  }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| asset.group.id | Unique identifier for the group. | keyword |
| asset.group.name | Name of the group. | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. | constant_keyword |
| event.kind | The event kind. | constant_keyword |
| event.message | Log message optimized for viewing in a log viewer. | text |
| event.module | Name of the module this data is coming from. | constant_keyword |
| event.provider | The event kind. | constant_keyword |
| event.start | `event.start` contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| labels | Custom key/value pairs. Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword. Example: `docker` and `k8s` labels. | object |
| labels.identity_source | Unique identifier for the identity source. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| user.email | User email address. | keyword |
| user.enabled | User account enabled status. | boolean |
| user.first_name | User first (given) name. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.full_name.text | Multi-field of `user.full_name`. | match_only_text |
| user.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.group.name | Name of the group. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.job_title | User's job title. | keyword |
| user.last_name | User last (surname) name. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.phone | User's phone numbers. | keyword |
| user.work.location | User's work location. | keyword |

