# Mattermost Integration

The Mattermost integration collects logs from [Mattermost](
https://docs.mattermost.com/) servers.  This integration has been tested with
Mattermost version 5.31.9 but is expected to work with other versions.

## Logs

### Audit

All access to the Mattermost REST API or CLI is audited.

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
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| group.id | Unique identifier for the group on the system/platform. | keyword |
| group.name | Name of the group. | keyword |
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
| http.response.status_code | HTTP response status code. | long |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| mattermost.audit.api_path | REST API endpoint | keyword |
| mattermost.audit.channel.id | ID of affected channel | keyword |
| mattermost.audit.channel.name | Name of affected channel | keyword |
| mattermost.audit.channel.type | Type of affected channel | keyword |
| mattermost.audit.cluster.id | Mattermost cluster ID | keyword |
| mattermost.audit.error.message | Mattermost error message | keyword |
| mattermost.audit.patch.id | ID of patched channel/team/user... | keyword |
| mattermost.audit.patch.name | Name of patched channel/team/user... | keyword |
| mattermost.audit.patch.roles | Roles of patched user | keyword |
| mattermost.audit.patch.type | Type of patched channel/team/user... | keyword |
| mattermost.audit.post.channel.id | Channel ID of post | keyword |
| mattermost.audit.post.id | Post ID | keyword |
| mattermost.audit.post.pinned | Whether or not the post was pinned to the channel | boolean |
| mattermost.audit.related.channel | List of channels realted to the event | keyword |
| mattermost.audit.related.team | List of channels realted to the event | keyword |
| mattermost.audit.session.id | ID of session used to call the API | keyword |
| mattermost.audit.status | Outcome of action/event, ex. success, fail, attempt... | keyword |
| mattermost.audit.team.id | ID of affected team | keyword |
| mattermost.audit.team.name | Name of affected team | keyword |
| mattermost.audit.team.type | Type of affected team | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| user.changes.name | Short name or login of the user. | keyword |
| user.changes.name.text | Multi-field of `user.changes.name`. | match_only_text |
| user.id | Unique identifier of the user. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| user.target.name.text | Multi-field of `user.target.name`. | match_only_text |
| user.target.roles | Array of user roles at the time of the event. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


An example event for `audit` looks as following:

```json
{
    "@timestamp": "2021-12-04T23:19:32.051Z",
    "agent": {
        "ephemeral_id": "3a1ecfb2-18a4-46c9-9996-65f6853ed739",
        "id": "d2a14a09-96fc-4f81-94ef-b0cd75ad71e7",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "mattermost.audit",
        "namespace": "26102",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "d2a14a09-96fc-4f81-94ef-b0cd75ad71e7",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "updateConfig",
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "dataset": "mattermost.audit",
        "ingested": "2024-06-12T03:15:44Z",
        "kind": "event",
        "original": "{\"timestamp\":\"2021-12-04 23:19:32.051 Z\",\"event\":\"updateConfig\",\"status\":\"success\",\"user_id\":\"ag99yu4i1if63jrui63tsmq57y\",\"session_id\":\"pjh4n69j3p883k7hhzippskcba\",\"ip_address\":\"172.19.0.1\",\"api_path\":\"/api/v4/config\",\"cluster_id\":\"jq3utry71f8a7q9qgebmjccf4r\",\"client\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36\"}",
        "outcome": "success",
        "type": [
            "change"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "172.19.0.7"
        ],
        "mac": [
            "02-42-AC-13-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "6.5.11-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/audit.log"
        },
        "offset": 0
    },
    "mattermost": {
        "audit": {
            "api_path": "/api/v4/config",
            "cluster": {
                "id": "jq3utry71f8a7q9qgebmjccf4r"
            },
            "session": {
                "id": "pjh4n69j3p883k7hhzippskcba"
            }
        }
    },
    "related": {
        "ip": [
            "172.19.0.1"
        ],
        "user": [
            "ag99yu4i1if63jrui63tsmq57y"
        ]
    },
    "source": {
        "address": "172.19.0.1",
        "ip": "172.19.0.1"
    },
    "tags": [
        "mattermost-audit",
        "preserve_original_event"
    ],
    "url": {
        "original": "/api/v4/config",
        "path": "/api/v4/config"
    },
    "user": {
        "id": "ag99yu4i1if63jrui63tsmq57y"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Chrome",
        "original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
        "os": {
            "full": "Windows 10",
            "name": "Windows",
            "version": "10"
        },
        "version": "96.0.4664.45"
    }
}
```
