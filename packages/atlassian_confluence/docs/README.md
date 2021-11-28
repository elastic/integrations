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
| confluence.audit.changed_values | Changed Values | flattened |
| confluence.audit.extra_attributes | Extra Attributes | flattened |
| confluence.audit.method | Method | keyword |
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
| user.changes.email | User email address. | keyword |
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
    "confluence": {
        "audit": {
            "method": "Browser",
            "affected_objects": [
                {
                    "name": "asdf",
                    "id": "2c9680837d4a3682017d67821e520003",
                    "type": "User",
                    "uri": "http://confluence.internal:8090/admin/users/viewuser.action?username=asdf123"
                }
            ],
            "type": {
                "actionI18nKey": "audit.logging.summary.user.renamed",
                "action": "User renamed",
                "categoryI18nKey": "audit.logging.category.user.management",
                "category": "Users and groups"
            },
            "changed_values": [
                {
                    "from": "asdf",
                    "to": "asdf123",
                    "i18nKey": "audit.logging.changed.value.username",
                    "key": "Username"
                }
            ]
        }
    },
    "@timestamp": "2021-11-28T17:05:37.142Z",
    "ecs": {
        "version": "1.12.0"
    },
    "related": {
        "user": [
            "admin123",
            "asdf",
            "asdf123"
        ],
        "hosts": [
            "confluence.internal"
        ],
        "ip": [
            "10.100.100.2"
        ]
    },
    "service": {
        "address": "http://confluence.internal:8090"
    },
    "source": {
        "address": "10.100.100.2",
        "ip": "10.100.100.2"
    },
    "event": {
        "action": "audit.logging.summary.user.renamed",
        "ingested": "2021-11-28T17:41:58.711683518Z",
        "original": "{\"timestamp\":\"2021-11-28T17:05:37.142Z\",\"author\":{\"name\":\"Joe Bob\",\"type\":\"user\",\"id\":\"2c9680837d4a3682017d4a375a280000\",\"uri\":\"http://confluence.internal:8090/admin/users/viewuser.action?username=admin123\",\"avatarUri\":\"\"},\"type\":{\"categoryI18nKey\":\"audit.logging.category.user.management\",\"category\":\"Users and groups\",\"actionI18nKey\":\"audit.logging.summary.user.renamed\",\"action\":\"User renamed\"},\"affectedObjects\":[{\"name\":\"asdf\",\"type\":\"User\",\"uri\":\"http://confluence.internal:8090/admin/users/viewuser.action?username=asdf123\",\"id\":\"2c9680837d4a3682017d67821e520003\"}],\"changedValues\":[{\"key\":\"Username\",\"i18nKey\":\"audit.logging.changed.value.username\",\"from\":\"asdf\",\"to\":\"asdf123\"}],\"source\":\"10.100.100.2\",\"system\":\"http://confluence.internal:8090\",\"method\":\"Browser\",\"extraAttributes\":[]}",
        "type": [
            "user",
            "change"
        ],
        "category": [
            "iam"
        ],
        "kind": "event"
    },
    "user": {
        "name": "admin123",
        "changes": {
            "name": "asdf123"
        },
        "full_name": "Joe Bob",
        "id": "2c9680837d4a3682017d4a375a280000",
        "target": {
            "name": "asdf"
        }
    },
    "tags": [
        "preserve_original_event"
    ]
}
```