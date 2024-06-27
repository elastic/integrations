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
