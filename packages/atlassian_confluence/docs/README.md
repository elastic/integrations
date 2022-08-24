# Atlassian Confluence Integration

The Confluence integration collects [audit logs](https://confluence.atlassian.com/doc/auditing-in-confluence-829076528.html) from the audit log files or the [audit API](https://developer.atlassian.com/cloud/confluence/rest/api-group-audit/).

## Logs

### Audit

The Confluence integration collects audit logs from the audit log files or the audit API from self hosted Confluence Data Center. It has been tested with Confluence 7.14.2 but is expected to work with newer versions. As of version 1.2.0, this integration added experimental support for Atlassian Confluence Cloud.  JIRA Cloud only supports Basic Auth using username and a Personal Access Token.

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
| confluence.audit.external_collaborator | Whether the user is an external collaborator user | boolean |
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
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
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
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
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
| user.changes.full_name.text | Multi-field of `user.changes.full_name`. | match_only_text |
| user.changes.name | Short name or login of the user. | keyword |
| user.changes.name.text | Multi-field of `user.changes.name`. | match_only_text |
| user.full_name | User's full name, if available. | keyword |
| user.full_name.text | Multi-field of `user.full_name`. | match_only_text |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.target.email | User email address. | keyword |
| user.target.full_name | User's full name, if available. | keyword |
| user.target.full_name.text | Multi-field of `user.target.full_name`. | match_only_text |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| user.target.name.text | Multi-field of `user.target.name`. | match_only_text |


An example event for `audit` looks as following:

```json
{
    "@timestamp": "2021-11-23T00:41:45.280Z",
    "agent": {
        "ephemeral_id": "a362a4c6-e4c0-441d-9bca-edd06245f232",
        "id": "82d0dfd8-3946-4ac0-a092-a9146a71e3f7",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0-beta1"
    },
    "confluence": {
        "audit": {
            "extra_attributes": [
                {
                    "name": "ID Range",
                    "nameI18nKey": "atlassian.audit.event.attribute.id",
                    "value": "77 - 176"
                },
                {
                    "name": "Query",
                    "nameI18nKey": "atlassian.audit.event.attribute.query"
                },
                {
                    "name": "Results returned",
                    "nameI18nKey": "atlassian.audit.event.attribute.results",
                    "value": "100"
                },
                {
                    "name": "Timestamp Range",
                    "nameI18nKey": "atlassian.audit.event.attribute.timestamp",
                    "value": "2021-11-23T00:39:37.155Z - 2021-11-23T00:41:17.165Z"
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
    "data_stream": {
        "dataset": "atlassian_confluence.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "82d0dfd8-3946-4ac0-a092-a9146a71e3f7",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "action": "atlassian.audit.event.action.audit.search",
        "agent_id_status": "verified",
        "created": "2021-12-24T00:49:08.197Z",
        "dataset": "atlassian_confluence.audit",
        "ingested": "2021-12-24T00:49:09Z",
        "kind": "event",
        "original": "{\"affectedObjects\":[],\"author\":{\"avatarUri\":\"\",\"id\":\"2c9680837d4a3682017d4a375a280000\",\"name\":\"test user\",\"type\":\"user\",\"uri\":\"http://confluence.internal:8090/admin/users/viewuser.action?username=admin\"},\"changedValues\":[],\"extraAttributes\":[{\"name\":\"ID Range\",\"nameI18nKey\":\"atlassian.audit.event.attribute.id\",\"value\":\"77 - 176\"},{\"name\":\"Query\",\"nameI18nKey\":\"atlassian.audit.event.attribute.query\",\"value\":\"\"},{\"name\":\"Results returned\",\"nameI18nKey\":\"atlassian.audit.event.attribute.results\",\"value\":\"100\"},{\"name\":\"Timestamp Range\",\"nameI18nKey\":\"atlassian.audit.event.attribute.timestamp\",\"value\":\"2021-11-23T00:39:37.155Z - 2021-11-23T00:41:17.165Z\"}],\"method\":\"Browser\",\"source\":\"81.2.69.143\",\"system\":\"http://confluence.internal:8090\",\"timestamp\":\"2021-11-23T00:41:45.280Z\",\"type\":{\"action\":\"Audit Log search performed\",\"actionI18nKey\":\"atlassian.audit.event.action.audit.search\",\"category\":\"Auditing\",\"categoryI18nKey\":\"atlassian.audit.event.category.audit\"}}",
        "type": "info"
    },
    "input": {
        "type": "httpjson"
    },
    "related": {
        "hosts": [
            "confluence.internal"
        ],
        "ip": [
            "81.2.69.143"
        ],
        "user": [
            "admin"
        ]
    },
    "service": {
        "address": "http://confluence.internal:8090"
    },
    "source": {
        "address": "81.2.69.143",
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.143"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "confluence-audit"
    ],
    "user": {
        "full_name": "test user",
        "id": "2c9680837d4a3682017d4a375a280000",
        "name": "admin"
    }
}
```