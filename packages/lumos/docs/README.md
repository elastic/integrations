# Lumos Integration

The Lumos integration uses [Lumos' API](https://www.lumos.com/) to retrieve Activity Logs and ingest them into Elasticsearch. This allows you to search, observe, and visualize the Activity Logs through Elasticsearch.

The Elastic agent running this integration interacts with Lumos' infrastructure using their APIs to retrieve Activity Logs for a Lumos tenant.

## Configuration

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**
2. In the "Search for integrations" search bar type **Lumos**.
3. Click on "Lumos" integration from the search results.
4. Click on **Add Lumos** button to add Lumos integration.

### Configure Lumos Activity Logs data stream

1. In Lumos go to **Settings > API Tokens**
2. Click on "Add API Token", enter a name and description
3. Copy the key starting with `lsk_`
4. While adding Lumos integration in Elastic, paste your key into the `API Token` field

## Logs

### Activity Logs

Activity Logs summarize the history of changes and events occurring within Lumos.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Input type | keyword |
| lumos.activity_logs.actor.actor_type | The type of actor | keyword |
| lumos.activity_logs.actor.email | The email of the actor | keyword |
| lumos.activity_logs.actor.family_name | The family name of the actor | keyword |
| lumos.activity_logs.actor.given_name | The given name of the actor | keyword |
| lumos.activity_logs.event_began_at | The time the event began | keyword |
| lumos.activity_logs.event_type_user_friendly | The user friendly type of the event | keyword |
| lumos.activity_logs.targets.name |  | keyword |
| lumos.activity_logs.targets.target_type |  | keyword |


An example event for `activity` looks as following:

```json
{
    "@timestamp": "2025-10-07T10:29:39.283Z",
    "agent": {
        "ephemeral_id": "2899cf43-154c-43bf-8e38-6dd8fcdddeb8",
        "id": "ec7a2ba3-4ffe-4b9d-98cf-dce8eccd9455",
        "name": "elastic-agent-76548",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "lumos.activity_logs",
        "namespace": "18028",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ec7a2ba3-4ffe-4b9d-98cf-dce8eccd9455",
        "snapshot": false,
        "version": "8.19.4"
    },
    "event": {
        "action": "SOD_POLICY_DELETED",
        "agent_id_status": "verified",
        "created": "2025-10-07T10:29:39.283Z",
        "dataset": "lumos.activity_logs",
        "id": "630b90cedc35a8a5f43361534099bee51e032f42dd442085fc76ef094d228f543c78fbe59c132df992cf71a6b8496504e8ebbc6020fbae1f34206676985412e7",
        "ingested": "2025-10-07T10:29:42Z",
        "kind": "event",
        "outcome": "success",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "elastic-agent-76548",
        "ip": [
            "192.168.241.2",
            "192.168.240.4"
        ],
        "mac": [
            "12-2A-F7-F2-2C-D7",
            "DE-BF-74-CA-85-68"
        ],
        "name": "elastic-agent-76548",
        "os": {
            "kernel": "5.15.0-156-generic",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "input": {
        "type": "httpjson"
    },
    "lumos": {
        "activity_logs": {
            "actor": {
                "actor_type": "Lumos user",
                "email": "wile.e.coyote@lumos.com",
                "family_name": "Wile",
                "given_name": "Coyote"
            },
            "event_began_at": "2024-03-12T16:09:14",
            "event_type_user_friendly": "A user deleted a SOD Policy",
            "targets": [
                {
                    "name": "Untitled Rule",
                    "target_type": "SOD Policy"
                }
            ]
        }
    },
    "message": "{\"actor\":{\"actor_type\":\"Lumos user\",\"email\":\"wile.e.coyote@lumos.com\",\"family_name\":\"Wile\",\"given_name\":\"Coyote\"},\"event_began_at\":\"2024-03-12T16:09:14\",\"event_hash\":\"630b90cedc35a8a5f43361534099bee51e032f42dd442085fc76ef094d228f543c78fbe59c132df992cf71a6b8496504e8ebbc6020fbae1f34206676985412e7\",\"event_metadata\":{},\"event_type\":\"SOD_POLICY_DELETED\",\"event_type_user_friendly\":\"A user deleted a SOD Policy\",\"outcome\":\"Succeeded\",\"targets\":[{\"name\":\"Untitled Rule\",\"target_type\":\"SOD Policy\"}]}"
}
```