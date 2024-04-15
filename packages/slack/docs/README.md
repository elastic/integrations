# Slack Integration

[Slack](https://www.slack.com) is used by numerous orgazations as their primary chat and collaboration tool.

The Slack integration uses [Slack's API](https://api.slack.com/) to retrieve audit events and ingest them into Elasticsearch. This allows you to search, observe, and visualize the Slack log events through Elasticsearch.

The Elastic agent running this integration interacts with Slack's infrastructure using their APIs to retrieve [audit logs](https://api.slack.com/admins/audit-logs) for a workspace or enterprise.

**Please note the Audit Logs API is only available to Slack workspaces on an Enterprise Grid plan. These API methods will not work for workspaces on a Free, Standard, or Business+ plan.**

## Configuration

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**
2. In the "Search for integrations" search bar type **Slack**.
3. Click on "Slack" integration from the search results.
4. Click on **Add Slack** button to add Slack integration.

### Configure Slack audit logs data stream

Enter values "OAuth API Token".

1. [**OAuth API Token**](https://api.slack.com/authentication/basics) will be generated when a [Slack App](https://api.slack.com/apps) is created.

#### Configure using API Token

For the Slack integration to be able to successfully get logs the following "User Token Scopes"" must be granted to the Slack App:

- `auditlogs:read`

## Logs

### Audit

Audit logs summarize the history of changes made within the Slack Enterprise.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | The cloud project identifier. Examples: Google Cloud Project id, Azure Project id. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host, resource, or service is located. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| slack.audit.context.domain | The domain of the Workspace or Enterprise | keyword |
| slack.audit.context.id | The ID of the workspace or enterprise | keyword |
| slack.audit.context.name | The name of the workspace or enterprise | keyword |
| slack.audit.context.session_id | The identifier that is unique to each authenticated session. | keyword |
| slack.audit.context.type | The type of account.  Either `Workspace` or `Enterprise` | keyword |
| slack.audit.details.location | The location the activity occured in when event.action is anomaly | keyword |
| slack.audit.details.md5 | The md5 hash of a file associated with a `file_malicious_content_detected` event. | keyword |
| slack.audit.details.previous_ip_address | The IP address previously observed for the entity in the event when event.action is anomaly | ip |
| slack.audit.details.previous_user_agent | The User-Agent string previously observed for the entity in the event when event.action is anomaly | keyword |
| slack.audit.details.reason | The anomaly rule triggered to generate the event when event.action is anomaly: asn, excessive_downloads, ip_address, session_fingerprint, tor, user_agent | keyword |
| slack.audit.entity.barriered_from_usergroup | The user group barrier when entity_type is barrier | keyword |
| slack.audit.entity.channel | The channel the entity is within when entity_type is message | keyword |
| slack.audit.entity.domain | Domain of the entity when entity_type is Workspace or Enterprise | keyword |
| slack.audit.entity.email | Email address of the entity when entity_type is user | keyword |
| slack.audit.entity.entity_type | Type of the entity: workspace, enterprise, user, file, channel, app, workflow, user, usergroup, barrier, message, role, account_type_role. | keyword |
| slack.audit.entity.filetype | Filetype of the entity when entity_type is file | keyword |
| slack.audit.entity.id | ID of the entity | keyword |
| slack.audit.entity.is_directory_approved | If App is approved when entity_type is app | boolean |
| slack.audit.entity.is_distributed | If App is distributed when entity_type is app | boolean |
| slack.audit.entity.is_org_shared | If channel is shared when entity_type is channel | boolean |
| slack.audit.entity.is_shared | If channel is shared when entity_type is channel | boolean |
| slack.audit.entity.is_workflow_app | If App is a workflow when entity_type is app | boolean |
| slack.audit.entity.name | Name of the entity | keyword |
| slack.audit.entity.primary_usergroup | The primary user group when entity_type is barrier | keyword |
| slack.audit.entity.privacy | Privacy status of entity when entity_type is channel | keyword |
| slack.audit.entity.scopes | The OAuth scopes when entity_type is app | keyword |
| slack.audit.entity.team | Team that the entity exists within when entity_type is user or message | keyword |
| slack.audit.entity.teams_shared_with | List of orgs channel is shared with when entity_type is channel | keyword |
| slack.audit.entity.timestamp | The timestamp of the entity when entity_type is message | keyword |
| slack.audit.entity.title | Title of the entity when entity_type is file | keyword |
| slack.audit.entity.type | The type of the entity when entity_type is role | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
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
| user.email | User email address. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.full_name.text | Multi-field of `user.full_name`. | match_only_text |
| user.id | Unique identifier of the user. | keyword |
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
    "@timestamp": "2023-01-13T17:40:21.862Z",
    "agent": {
        "ephemeral_id": "a3daca3b-553f-45eb-8bfb-8a95e6e5631e",
        "id": "f25d13cd-18cc-4e73-822c-c4f849322623",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "data_stream": {
        "dataset": "slack.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "f25d13cd-18cc-4e73-822c-c4f849322623",
        "snapshot": false,
        "version": "8.10.1"
    },
    "event": {
        "action": "anomaly",
        "agent_id_status": "verified",
        "created": "2023-09-22T17:50:16.870Z",
        "dataset": "slack.audit",
        "id": "1665fc41-c67c-4cf5-a5c4-d90cb58dd5f9",
        "ingested": "2023-09-22T17:50:17Z",
        "kind": "event",
        "original": "{\"action\":\"anomaly\",\"actor\":{\"type\":\"user\",\"user\":{\"email\":\"aaron@demo.com\",\"id\":\"e65b0f5c\",\"name\":\"roy\"}},\"context\":{\"ip_address\":\"81.2.69.143\",\"location\":{\"domain\":\"Docker\",\"id\":\"e65b11aa\",\"name\":\"Docker\",\"type\":\"workspace\"},\"ua\":\"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:23.0) Gecko/20131011 Firefox/23.0\"},\"date_create\":1683836291,\"details\":{\"action_timestamp\":1673631621862,\"location\":\"England, GB\",\"previous_ip_address\":\"175.16.199.64\",\"previous_ua\":\"\",\"reason\":[\"asn\",\"ip_address\"]},\"entity\":{\"type\":\"user\",\"user\":{\"email\":\"jbob@example.com\",\"id\":\"asdfasdf\",\"name\":\"Joe Bob\",\"team\":\"T234SAH2\"}},\"id\":\"1665fc41-c67c-4cf5-a5c4-d90cb58dd5f9\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "related": {
        "ip": [
            "81.2.69.143"
        ],
        "user": [
            "e65b0f5c",
            "aaron@demo.com"
        ]
    },
    "slack": {
        "audit": {
            "context": {
                "domain": "Docker",
                "id": "e65b11aa",
                "name": "Docker",
                "type": "workspace"
            },
            "details": {
                "location": "England, GB",
                "previous_ip_address": "175.16.199.64",
                "reason": [
                    "asn",
                    "ip_address"
                ]
            },
            "entity": {
                "email": "jbob@example.com",
                "entity_type": "user",
                "id": "asdfasdf",
                "name": "Joe Bob",
                "team": "T234SAH2"
            }
        }
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
        "forwarded",
        "slack-audit",
        "preserve_original_event"
    ],
    "user": {
        "email": "aaron@demo.com",
        "full_name": "roy",
        "id": "e65b0f5c"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Firefox",
        "original": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:23.0) Gecko/20131011 Firefox/23.0",
        "os": {
            "full": "Windows 7",
            "name": "Windows",
            "version": "7"
        },
        "version": "23.0."
    }
}

```
