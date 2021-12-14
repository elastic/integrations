# Atlassian Bitbucket Integration

The Bitbucket integration collects audit logs from the audit log files or the audit API.

## Logs

### Audit

The Bitbucket integration collects audit logs from the audit log files or the audit API from self hosted Bitbucket Data Center. It has been tested with Bitbucket 7.18.1 but is expected to work with newer versions.  This has not been tested with Bitbucket Cloud and is not expected to work.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| bitbucket.audit.affected_objects | Affected Objects | flattened |
| bitbucket.audit.changed_values | Changed Values | flattened |
| bitbucket.audit.extra_attributes | Extra Attributes | flattened |
| bitbucket.audit.method | Method | keyword |
| bitbucket.audit.type.action | Action | keyword |
| bitbucket.audit.type.actionI18nKey | actionI18nKey | keyword |
| bitbucket.audit.type.area | Area | keyword |
| bitbucket.audit.type.category | Category | keyword |
| bitbucket.audit.type.categoryI18nKey | categoryI18nKey | keyword |
| bitbucket.audit.type.level | Audit Level | keyword |
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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset | Log offset | long |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.domain | Source domain. | keyword |
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
| user.changes.full_name | User's full name, if available. | keyword |
| user.changes.name | Short name or login of the user. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.full_name | User's full name, if available. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |


An example event for `audit` looks as following:

```json
{
    "@timestamp": "2021-11-27T18:13:19.888Z",
    "agent": {
        "ephemeral_id": "e1941192-7059-4772-9f71-653aed65d6dd",
        "hostname": "docker-fleet-agent",
        "id": "20fcdc33-b3b1-4e34-9205-89a344ebbdb0",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.16.0"
    },
    "bitbucket": {
        "audit": {
            "affected_objects": [
                {
                    "id": "3",
                    "name": "AT",
                    "type": "PROJECT"
                }
            ],
            "extra_attributes": [
                {
                    "name": "target",
                    "nameI18nKey": "bitbucket.audit.attribute.legacy.target",
                    "value": "AT"
                }
            ],
            "method": "Browser",
            "type": {
                "action": "Project deletion requested",
                "actionI18nKey": "bitbucket.service.project.audit.action.projectdeletionrequested",
                "area": "LOCAL_CONFIG_AND_ADMINISTRATION",
                "category": "Projects",
                "categoryI18nKey": "bitbucket.service.audit.category.projects",
                "level": "BASE"
            }
        }
    },
    "data_stream": {
        "dataset": "atlassian_bitbucket.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "1.12.0"
    },
    "elastic_agent": {
        "id": "20fcdc33-b3b1-4e34-9205-89a344ebbdb0",
        "snapshot": true,
        "version": "7.16.0"
    },
    "event": {
        "action": "bitbucket.service.project.audit.action.projectdeletionrequested",
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "dataset": "atlassian_bitbucket.audit",
        "ingested": "2021-12-08T15:18:06Z",
        "kind": "event",
        "original": "{\"affectedObjects\":[{\"id\":\"3\",\"name\":\"AT\",\"type\":\"PROJECT\"}],\"auditType\":{\"action\":\"Project deletion requested\",\"actionI18nKey\":\"bitbucket.service.project.audit.action.projectdeletionrequested\",\"area\":\"LOCAL_CONFIG_AND_ADMINISTRATION\",\"category\":\"Projects\",\"categoryI18nKey\":\"bitbucket.service.audit.category.projects\",\"level\":\"BASE\"},\"author\":{\"id\":\"2\",\"name\":\"admin\",\"type\":\"NORMAL\"},\"changedValues\":[],\"extraAttributes\":[{\"name\":\"target\",\"nameI18nKey\":\"bitbucket.audit.attribute.legacy.target\",\"value\":\"AT\"}],\"method\":\"Browser\",\"node\":\"8767044c-1b98-4d64-82db-ef29af8c3792\",\"source\":\"10.100.100.2\",\"system\":\"http://bitbucket.internal:7990\",\"timestamp\":{\"epochSecond\":1638036799,\"nano\":888000000},\"version\":\"1.0\"}",
        "type": [
            "deletion"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "83a5cd10d1960dd73f42bd2801d238c3",
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
            "kernel": "5.4.0-90-generic",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/test-audit.log"
        },
        "offset": 0
    },
    "related": {
        "hosts": [
            "bitbucket.internal"
        ],
        "ip": [
            "10.100.100.2"
        ],
        "user": [
            "admin"
        ]
    },
    "service": {
        "address": "http://bitbucket.internal:7990"
    },
    "source": {
        "address": "10.100.100.2",
        "ip": "10.100.100.2"
    },
    "tags": [
        "preserve_original_event",
        "bitbucket-audit"
    ],
    "user": {
        "id": "2",
        "name": "admin"
    }
}
```