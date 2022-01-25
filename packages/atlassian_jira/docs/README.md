# Atlassian Jira Integration

The Jira integration collects audit logs from the audit log files or the audit API.

## Logs

### Audit

The Jira integration collects audit logs from the audit log files or the audit API from self hosted Jira Data Center. It has been tested with Jira 8.20.2 but is expected to work with newer versions.  This has not been tested with Jira Cloud and is not expected to work.

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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
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
| jira.audit.affected_objects | Affected Objects | flattened |
| jira.audit.changed_values | Changed Values | flattened |
| jira.audit.extra_attributes | Extra Attributes | flattened |
| jira.audit.method | Method | keyword |
| jira.audit.type.action | Action | keyword |
| jira.audit.type.actionI18nKey | actionI18nKey | keyword |
| jira.audit.type.area | Area | keyword |
| jira.audit.type.category | Category | keyword |
| jira.audit.type.categoryI18nKey | categoryI18nKey | keyword |
| jira.audit.type.level | Audit Level | keyword |
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
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
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
| user.changes.email | User email address. | keyword |
| user.changes.full_name | User's full name, if available. | keyword |
| user.changes.name | Short name or login of the user. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.email | User email address. | keyword |
| user.target.full_name | User's full name, if available. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |


An example event for `audit` looks as following:

```json
{
    "@timestamp": "2021-11-22T00:31:52.991Z",
    "agent": {
        "ephemeral_id": "970494dc-6fd0-4e64-bd87-6d1fc7deba3f",
        "id": "82d0dfd8-3946-4ac0-a092-a9146a71e3f7",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "atlassian_jira.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "82d0dfd8-3946-4ac0-a092-a9146a71e3f7",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "action": "atlassian.audit.event.action.audit.search",
        "agent_id_status": "verified",
        "created": "2021-12-24T00:59:55.629Z",
        "dataset": "atlassian_jira.audit",
        "ingested": "2021-12-24T00:59:56Z",
        "kind": "event",
        "original": "{\"affectedObjects\":[],\"author\":{\"avatarUri\":\"\",\"id\":\"10000\",\"name\":\"test.user\",\"type\":\"ApplicationUser\",\"uri\":\"http://jira.internal:8088/secure/ViewProfile.jspa?name=test.user\"},\"changedValues\":[],\"extraAttributes\":[{\"name\":\"ID Range\",\"nameI18nKey\":\"atlassian.audit.event.attribute.id\",\"value\":\"41 - 90\"},{\"name\":\"Query\",\"nameI18nKey\":\"atlassian.audit.event.attribute.query\",\"value\":\"\"},{\"name\":\"Results returned\",\"nameI18nKey\":\"atlassian.audit.event.attribute.results\",\"value\":\"50\"},{\"name\":\"Timestamp Range\",\"nameI18nKey\":\"atlassian.audit.event.attribute.timestamp\",\"value\":\"2021-11-22T00:08:33.887Z - 2021-11-22T00:31:37.412Z\"}],\"method\":\"Browser\",\"source\":\"10.50.33.72\",\"system\":\"http://jira.internal:8088\",\"timestamp\":\"2021-11-22T00:31:52.991Z\",\"type\":{\"action\":\"Audit Log search performed\",\"actionI18nKey\":\"atlassian.audit.event.action.audit.search\",\"category\":\"Auditing\",\"categoryI18nKey\":\"atlassian.audit.event.category.audit\"}}",
        "type": "info"
    },
    "input": {
        "type": "httpjson"
    },
    "jira": {
        "audit": {
            "extra_attributes": [
                {
                    "name": "ID Range",
                    "nameI18nKey": "atlassian.audit.event.attribute.id",
                    "value": "41 - 90"
                },
                {
                    "name": "Query",
                    "nameI18nKey": "atlassian.audit.event.attribute.query"
                },
                {
                    "name": "Results returned",
                    "nameI18nKey": "atlassian.audit.event.attribute.results",
                    "value": "50"
                },
                {
                    "name": "Timestamp Range",
                    "nameI18nKey": "atlassian.audit.event.attribute.timestamp",
                    "value": "2021-11-22T00:08:33.887Z - 2021-11-22T00:31:37.412Z"
                }
            ],
            "method": "Browser",
            "type": {
                "action": "Audit Log search performed",
                "actionI18nKey": "atlassian.audit.event.action.audit.search",
                "category": "Auditing",
                "categoryI18nKey": "atlassian.audit.event.category.audit"
            }
        }
    },
    "related": {
        "hosts": [
            "jira.internal"
        ],
        "ip": [
            "10.50.33.72"
        ],
        "user": [
            "test.user"
        ]
    },
    "service": {
        "address": "http://jira.internal:8088"
    },
    "source": {
        "address": "10.50.33.72",
        "ip": "10.50.33.72"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "jira-audit"
    ],
    "user": {
        "id": "10000",
        "name": "test.user"
    }
}
```