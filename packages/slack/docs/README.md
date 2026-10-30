# Slack Integration

[Slack](https://www.slack.com) is used by numerous orgazations as their primary chat and collaboration tool.

The Slack integration uses [Slack's API](https://api.slack.com/) to retrieve audit events and a user inventory, and ingest them into Elasticsearch. This allows you to search, observe, and visualize the Slack log events through Elasticsearch.

The Elastic agent running this integration interacts with Slack's infrastructure using their APIs to retrieve [audit logs](https://api.slack.com/admins/audit-logs), [Enterprise Grid users](https://docs.slack.dev/reference/methods/admin.users.list), and [user groups](https://docs.slack.dev/reference/methods/usergroups.list).

**Please note these APIs are only available to Slack workspaces on an Enterprise Grid plan. These API methods will not work for workspaces on a Free, Standard, or Business+ plan.**

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

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

For the Slack integration to be able to successfully get logs the following "User Token Scopes" must be granted to the Slack App:

- Audit logs: `auditlogs:read`
- Users: `admin.users:read`
- User groups: `usergroups:read`

The audit and users streams each have their own token. You can use one Slack app token that has all required scopes, or a separate token per stream. The users stream needs both `admin.users:read` and `usergroups:read`.

## Logs

### Audit

Audit logs summarize the history of changes made within the Slack Enterprise.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| slack.audit.actor.type | The type of entity performing the action. | keyword |
| slack.audit.actor.user.team | The the team of the actor if they are a user. | keyword |
| slack.audit.context.domain | The domain of the Workspace or Enterprise | keyword |
| slack.audit.context.id | The ID of the workspace or enterprise | keyword |
| slack.audit.context.name | The name of the workspace or enterprise | keyword |
| slack.audit.context.session_id | The identifier that is unique to each authenticated session. | keyword |
| slack.audit.context.type | The type of account. Either `Workspace` or `Enterprise` | keyword |
| slack.audit.details.arguments | The arguments an AI app passed to a Slack MCP server tool when event.action ends in `_tool_called`. The shape depends on the tool, so nested keys are stored as dotted leaf fields. | object |
| slack.audit.details.location | The location the activity occured in when event.action is anomaly | keyword |
| slack.audit.details.md5 | The md5 hash of a file associated with a `file_malicious_content_detected` event. | keyword |
| slack.audit.details.previous_ip_address | The IP address previously observed for the entity in the event when event.action is anomaly | ip |
| slack.audit.details.previous_user_agent | The User-Agent string previously observed for the entity in the event when event.action is anomaly | keyword |
| slack.audit.details.reason | The anomaly rule triggered to generate the event when event.action is anomaly: asn, excessive_downloads, ip_address, session_fingerprint, tor, user_agent | keyword |
| slack.audit.details.tool | The Slack MCP server tool an AI app called when event.action ends in `_tool_called`. | keyword |
| slack.audit.details.url_private | URL associated with the action. | keyword |
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


An example event for `audit` looks as following:

```json
{
    "@timestamp": "2023-01-13T17:40:21.862Z",
    "agent": {
        "ephemeral_id": "4493e0ba-0e9b-43e7-ad59-2a2c6c330c73",
        "id": "6790db85-6c1f-425a-a093-87887eed5a5d",
        "name": "elastic-agent-86233",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "slack.audit",
        "namespace": "54041",
        "type": "logs"
    },
    "ecs": {
        "version": "9.5.0"
    },
    "elastic_agent": {
        "id": "6790db85-6c1f-425a-a093-87887eed5a5d",
        "snapshot": false,
        "version": "8.19.4"
    },
    "event": {
        "action": "anomaly",
        "agent_id_status": "verified",
        "created": "2025-12-05T07:31:29.085Z",
        "dataset": "slack.audit",
        "id": "2125fb41-c67c-4cf5-a5c4-d90cb58dd5f9",
        "ingested": "2025-12-05T07:31:30Z",
        "kind": "event",
        "original": "{\"action\":\"anomaly\",\"actor\":{\"type\":\"user\",\"user\":{\"email\":\"aaron@demo.com\",\"id\":\"e65b0f5c\",\"name\":\"roy\"}},\"context\":{\"ip_address\":\"81.2.69.143\",\"location\":{\"domain\":\"Docker\",\"id\":\"e65b11aa\",\"name\":\"Docker\",\"type\":\"workspace\"},\"ua\":\"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:23.0) Gecko/20131011 Firefox/23.0\"},\"date_create\":1683836273,\"details\":{\"action_timestamp\":1673631621862,\"location\":\"England, GB\",\"previous_ip_address\":\"175.16.199.64\",\"previous_ua\":\"\",\"reason\":[\"asn\",\"ip_address\"]},\"entity\":{\"type\":\"user\",\"user\":{\"email\":\"jbob@example.com\",\"id\":\"asdfasdf\",\"name\":\"Joe Bob\",\"team\":\"T234SAH2\"}},\"id\":\"2125fb41-c67c-4cf5-a5c4-d90cb58dd5f9\"}",
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
            "actor": {
                "type": "user"
            },
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
        "version": "23.0"
    }
}
```

### Users

The users data stream collects a daily snapshot of Slack Enterprise Grid user accounts from [`admin.users.list`](https://docs.slack.dev/reference/methods/admin.users.list). Each document is one user, for Elastic Security entity analytics.

It then collects user groups from [`usergroups.list`](https://docs.slack.dev/reference/methods/usergroups.list) for each workspace on those users, and attaches matching groups to `slack.user.groups`. The **[Logs Slack Logs] Users** dashboard includes user and group panels.

The token must be an org-level user token (`xoxp-`) with the `admin.users:read` and `usergroups:read` scopes. The app must be installed on the Enterprise organization, not on a single workspace.

**Active Users Only** chooses which accounts are collected. Enabled collects active users. Disabled collects deactivated users. Slack cannot return both in one request.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| slack.user.date_created | When the Slack account was created. | date |
| slack.user.deactivated_ts | When the Slack account was deactivated. Absent when Slack sends 0. | date |
| slack.user.expiration_ts | When a guest account expires. Absent when Slack sends 0. | date |
| slack.user.groups.auto_type | Automatic user group type, such as admin or owner, when Slack sets one. | keyword |
| slack.user.groups.created_by | Slack user ID that created the user group. | keyword |
| slack.user.groups.date_create | When the user group was created. | date |
| slack.user.groups.date_delete | When the user group was deleted. Absent when Slack sends 0. | date |
| slack.user.groups.date_update | When the user group was last updated. | date |
| slack.user.groups.deleted_by | Slack user ID that deleted the user group. | keyword |
| slack.user.groups.description | User group description. | keyword |
| slack.user.groups.handle | User group mention handle. | keyword |
| slack.user.groups.id | Slack user group ID. | keyword |
| slack.user.groups.is_external | Whether the user group is external. | boolean |
| slack.user.groups.is_usergroup | Whether this object is a Slack user group. | boolean |
| slack.user.groups.name | User group name. | keyword |
| slack.user.groups.prefs.channels | Default public channel IDs for the user group. | keyword |
| slack.user.groups.prefs.groups | Default private channel IDs for the user group. | keyword |
| slack.user.groups.team_id | Workspace ID the user group belongs to. | keyword |
| slack.user.groups.updated_by | Slack user ID that last updated the user group. | keyword |
| slack.user.groups.user_count | Number of users in the user group, as returned by Slack. | keyword |
| slack.user.has_2fa | Whether the user has two-factor authentication enabled. Copied to user.entity.attributes.mfa_enabled. | boolean |
| slack.user.has_sso | Whether the user signs in with single sign-on. | boolean |
| slack.user.is_active | Whether the Slack account is active. Deactivated accounts are false. | boolean |
| slack.user.is_admin | Whether the user is an admin. | boolean |
| slack.user.is_bot | Whether the account is a bot. | boolean |
| slack.user.is_owner | Whether the user is an owner. | boolean |
| slack.user.is_primary_owner | Whether the user is the primary owner. | boolean |
| slack.user.is_restricted | Whether the user is a guest. | boolean |
| slack.user.is_ultra_restricted | Whether the user is a single-channel guest. | boolean |
| slack.user.last_active_ts | When Slack last recorded activity for the user. Copied to user.entity.lifecycle.last_activity. | date |
| slack.user.roles | Slack admin role IDs assigned to the user, when the API returns them. | keyword |
| slack.user.workspaces | Workspace IDs the user belongs to. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.email | User email address. | keyword |
| user.entity.attributes.mfa_enabled | Indicates whether multi-factor authentication is enabled for this entity. Typically applicable to User entities. | boolean |
| user.entity.display_name | An optional field used when a pretty name is desired for entity-centric operations. This field should not be used for correlation with `\*.name` fields for entities with dedicated field sets (for example, `host`). | keyword |
| user.entity.display_name.text | Multi-field of `user.entity.display_name`. | match_only_text |
| user.entity.id | A unique identifier for the entity. When multiple identifiers exist, this should be the most stable and commonly used identifier that: 1) persists across the entity's lifecycle, 2) ensures uniqueness within its scope, 3) is commonly used for queries and correlation, and 4) is readily available in most observations (logs/events). For entities with dedicated field sets (for example, host, user), this value should match the corresponding \*.id field. Alternative identifiers (for example, ARNs values in AWS, URLs) can be preserved in the raw field. | keyword |
| user.entity.last_seen_timestamp | Indicates the date/time when this entity was last "seen," usually based upon the last event/log that is initiated by this entity. | date |
| user.entity.lifecycle.last_activity | Timestamp of the most recent action performed by or attributed to this entity (active use). Distinct from `entity.last_seen_timestamp`, which records when the entity was last observed in data; `last_activity` implies the entity was active, not only seen. Typically applicable to User, Host, and Service entities. | date |
| user.entity.name | The name of the entity. The keyword field enables exact matches for filtering and aggregations, while the text field enables full-text search. For entities with dedicated field sets (for example, `host`), this field should mirrors the corresponding \*.name value. | keyword |
| user.entity.name.text | Multi-field of `user.entity.name`. | match_only_text |
| user.entity.source | The module or integration that provided this entity data (similar to event.module). | keyword |
| user.entity.sub_type | The specific type designation for the entity as defined by its provider or system. This field provides more granular classification than the type field. Examples: `aws_s3_bucket`, `gcp_cloud_storage_bucket`, `azure_blob_container` would all map to entity type `bucket`.  `hardware` , `virtual` , `container` , `node` , `cloud_instance` would all map to entity type `host`. | keyword |
| user.entity.type | A standardized high-level classification of the entity. This provides a normalized way to group similar entities across different providers or systems. Example values: `bucket`, `database`, `container`, `function`, `queue`, `host`, `user`, `application`, `session`, `cloud`, `orchestrator`, etc. If an entity is nested under a top-level namespace like `host` or `cloud`, or similar, its type array should include the matching value — for example, `host` or `cloud`. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.full_name.text | Multi-field of `user.full_name`. | match_only_text |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.roles | Array of user roles at the time of the event. | keyword |


An example event for `user` looks as following:

```json
{
    "@timestamp": "2026-10-29T09:05:16.637Z",
    "agent": {
        "ephemeral_id": "f7065e09-c62a-4d89-871c-285a7f7bc5d7",
        "id": "8584a241-b697-40e9-bc0e-146a6c3492a9",
        "name": "elastic-agent-12629",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "slack.user",
        "namespace": "92443",
        "type": "logs"
    },
    "ecs": {
        "version": "9.5.0"
    },
    "elastic_agent": {
        "id": "8584a241-b697-40e9-bc0e-146a6c3492a9",
        "snapshot": false,
        "version": "8.19.4"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "slack.user",
        "ingested": "2026-10-29T09:05:17Z",
        "kind": "asset",
        "original": "{\"date_created\":1566922090,\"deactivated_ts\":0,\"email\":\"alex.morgan@example.com\",\"expiration_ts\":0,\"full_name\":\"Alex Morgan\",\"groups\":[{\"auto_type\":null,\"created_by\":\"W0123ABC001\",\"date_create\":1446598059,\"date_delete\":0,\"date_update\":1446670362,\"deleted_by\":null,\"description\":\"Engineering team for the Elastic workspace.\",\"handle\":\"engineering\",\"id\":\"S0614TZR7\",\"is_external\":false,\"is_usergroup\":true,\"name\":\"Engineering\",\"prefs\":{\"channels\":[],\"groups\":[]},\"team_id\":\"T0123ABC456\",\"updated_by\":\"W0123ABC001\",\"user_count\":\"3\"},{\"auto_type\":\"admin\",\"created_by\":\"USLACKBOT\",\"date_create\":1446678371,\"date_delete\":0,\"date_update\":1446678371,\"deleted_by\":null,\"description\":\"Security reviewers.\",\"handle\":\"security\",\"id\":\"S06158AV7\",\"is_external\":false,\"is_usergroup\":true,\"name\":\"Security\",\"prefs\":{\"channels\":[],\"groups\":[]},\"team_id\":\"T0123ABC456\",\"updated_by\":\"USLACKBOT\",\"user_count\":\"1\"}],\"has_2fa\":true,\"has_sso\":true,\"id\":\"W0123ABC001\",\"is_active\":true,\"is_admin\":true,\"is_bot\":false,\"is_owner\":true,\"is_primary_owner\":false,\"is_restricted\":false,\"is_ultra_restricted\":false,\"last_active_ts\":1700000000,\"roles\":[\"Rl0J\"],\"username\":\"alex.morgan\",\"workspaces\":[\"T0123ABC456\"]}",
        "type": [
            "user",
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "user": [
            "alex.morgan",
            "Alex Morgan",
            "alex.morgan@example.com",
            "W0123ABC001"
        ]
    },
    "slack": {
        "user": {
            "date_created": "2019-08-27T16:08:10.000Z",
            "deactivated_ts": 0,
            "expiration_ts": 0,
            "groups": [
                {
                    "created_by": "W0123ABC001",
                    "date_create": 1446598059,
                    "date_delete": 0,
                    "date_update": 1446670362,
                    "description": "Engineering team for the Elastic workspace.",
                    "handle": "engineering",
                    "id": "S0614TZR7",
                    "is_external": false,
                    "is_usergroup": true,
                    "name": "Engineering",
                    "team_id": "T0123ABC456",
                    "updated_by": "W0123ABC001",
                    "user_count": "3"
                },
                {
                    "auto_type": "admin",
                    "created_by": "USLACKBOT",
                    "date_create": 1446678371,
                    "date_delete": 0,
                    "date_update": 1446678371,
                    "description": "Security reviewers.",
                    "handle": "security",
                    "id": "S06158AV7",
                    "is_external": false,
                    "is_usergroup": true,
                    "name": "Security",
                    "team_id": "T0123ABC456",
                    "updated_by": "USLACKBOT",
                    "user_count": "1"
                }
            ],
            "has_2fa": true,
            "has_sso": true,
            "is_active": true,
            "is_admin": true,
            "is_bot": false,
            "is_owner": true,
            "is_primary_owner": false,
            "is_restricted": false,
            "is_ultra_restricted": false,
            "last_active_ts": "2023-11-14T22:13:20.000Z",
            "roles": [
                "Rl0J"
            ],
            "workspaces": [
                "T0123ABC456"
            ]
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "slack-user"
    ],
    "user": {
        "email": "alex.morgan@example.com",
        "entity": {
            "attributes": {
                "mfa_enabled": true
            },
            "display_name": "Alex Morgan",
            "id": "W0123ABC001",
            "last_seen_timestamp": "2026-10-29T09:05:16.637Z",
            "lifecycle": {
                "last_activity": "2023-11-14T22:13:20.000Z"
            },
            "name": "alex.morgan",
            "source": "slack",
            "sub_type": [
                "member"
            ],
            "type": [
                "user"
            ]
        },
        "full_name": "Alex Morgan",
        "id": "W0123ABC001",
        "name": "alex.morgan",
        "roles": [
            "owner",
            "admin"
        ]
    }
}
```
