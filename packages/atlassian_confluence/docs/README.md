# Atlassian Confluence Integration

The Confluence integration collects audit logs from the audit log files or the audit API.

## Logs

### Audit

The Confluence integration collects audit logs from the audit log files or the audit API from self hosted Confluence Data Center. It has been tested with Confluence 7.14.2 but is expected to work with newer versions. This has not been tested with Confluence Cloud and is not expected to work.

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
| confluence.audit.affected_objects | Affected Objects | flattened |
| confluence.audit.changed_values | Extra Attributes | flattened |
| confluence.audit.extra_attributes | Extra Attributes | flattened |
| confluence.audit.method | Method | keyword |
| confluence.audit.system | Jira Base URI | keyword |
| confluence.audit.type.action | Action | keyword |
| confluence.audit.type.actionI18nKey | actionI18nKey | keyword |
| confluence.audit.type.area | Area | keyword |
| confluence.audit.type.category | Category | keyword |
| confluence.audit.type.categoryI18nKey | categoryI18nKey | keyword |
| confluence.audit.type.level | Audit Level | keyword |
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
| user.full_name | User's full name, if available. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |


An example event for `audit` looks as following:

```json
{
    "@timestamp": "2021-11-22T23:50:13.000Z",
    "confluence": {
        "audit": {
            "system": "http://confluence.internal:8090",
            "method": "Browser",
            "affected_objects": [
                {
                    "name": "Another User",
                    "type": "User",
                    "id": "2c9580827d4a06e8017d4a0e9dda0001"
                }
            ],
            "type": {
                "area": "USER_MANAGEMENT",
                "action": "User created",
                "actionI18nKey": "audit.logging.summary.user.created",
                "categoryI18nKey": "audit.logging.category.user.management",
                "category": "Users and groups",
                "level": "BASE"
            },
            "changed_values": [
                {
                    "i18nKey": "Display name",
                    "key": "Display name",
                    "to": "Another User"
                },
                {
                    "i18nKey": "Email",
                    "key": "Email",
                    "to": "another.user@example.como"
                },
                {
                    "i18nKey": "Username",
                    "key": "Username",
                    "to": "another.user"
                },
                {
                    "i18nKey": "Active",
                    "key": "Active",
                    "to": "Yes"
                }
            ]
        }
    },
    "ecs": {
        "version": "1.12.0"
    },
    "source": {
        "geo": {
            "continent_name": "Europe",
            "region_iso_code": "GB-ENG",
            "city_name": "London",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "region_name": "England",
            "location": {
                "lon": -0.0931,
                "lat": 51.5142
            }
        },
        "address": "81.2.69.143",
        "ip": "81.2.69.143"
    },
    "event": {
        "action": "audit.logging.summary.user.created",
        "ingested": "2021-11-23T00:55:00.408968252Z",
        "original": "{\"affectedObjects\":[{\"id\":\"2c9580827d4a06e8017d4a0e9dda0001\",\"name\":\"Another User\",\"type\":\"User\"}],\"auditType\":{\"action\":\"User created\",\"actionI18nKey\":\"audit.logging.summary.user.created\",\"area\":\"USER_MANAGEMENT\",\"category\":\"Users and groups\",\"categoryI18nKey\":\"audit.logging.category.user.management\",\"level\":\"BASE\"},\"author\":{\"id\":\"2c9580827d4a06e8017d4a07c3e10000\",\"name\":\"test.user\",\"type\":\"user\"},\"changedValues\":[{\"i18nKey\":\"Display name\",\"key\":\"Display name\",\"to\":\"Another User\"},{\"i18nKey\":\"Email\",\"key\":\"Email\",\"to\":\"another.user@example.como\"},{\"i18nKey\":\"Username\",\"key\":\"Username\",\"to\":\"another.user\"},{\"i18nKey\":\"Active\",\"key\":\"Active\",\"to\":\"Yes\"}],\"extraAttributes\":[],\"method\":\"Browser\",\"source\":\"81.2.69.143\",\"system\":\"http://confluence.internal:8090\",\"timestamp\":{\"epochSecond\":1637625013,\"nano\":842000000},\"version\":\"1.0\"}"
    },
    "user": {
        "full_name": "test.user",
        "id": "2c9580827d4a06e8017d4a07c3e10000"
    },
    "tags": [
        "preserve_original_event"
    ]
}
```