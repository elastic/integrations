# Lumos Integration

The Lumos integration uses [Lumos' API](https://api.lumos.com/) to retrieve Activity Logs and ingest them into Elasticsearch. This allows you to search, observe, and visualize the Activity Logs through Elasticsearch.

The Elastic agent running this integration interacts with Lumos' infrastructure using their APIs to retrieve [Activity Logs](https://api.lumos.com/activity_logs) for a Lumos tenant.

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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The activity that occurred | keyword |
| event.created | The time the event began | date |
| event.id | The event hash | keyword |
| event.module | Event module | constant_keyword |
| event.outcome | The outcome of the event, whether it succeeded or failed | keyword |
| input.type | Input type | keyword |
| lumos.activity_logs.actor.actor_type | The type of actor | keyword |
| lumos.activity_logs.actor.email | The email of the actor | keyword |
| lumos.activity_logs.actor.family_name | The family name of the actor | keyword |
| lumos.activity_logs.actor.given_name | The given name of the actor | keyword |
| lumos.activity_logs.event_began_at | The time the event began | keyword |
| lumos.activity_logs.event_type_user_friendly | The user friendly type of the event | keyword |
| lumos.activity_logs.targets.name |  | keyword |
| lumos.activity_logs.targets.target_type |  | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |


An example event for `activity` looks as following:

```json
{
    "@timestamp": "2024-06-12T03:14:31.761Z",
    "agent": {
        "ephemeral_id": "164152f0-95db-44c9-a369-1412cbf18efd",
        "id": "d2a14a09-96fc-4f81-94ef-b0cd75ad71e7",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "lumos.activity_logs",
        "namespace": "41003",
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
        "action": "SOD_POLICY_DELETED",
        "agent_id_status": "verified",
        "created": "2024-06-12T03:14:31.761Z",
        "dataset": "lumos.activity_logs",
        "id": "630b90cedc35a8a5f43361534099bee51e032f42dd442085fc76ef094d228f543c78fbe59c132df992cf71a6b8496504e8ebbc6020fbae1f34206676985412e7",
        "ingested": "2024-06-12T03:14:43Z",
        "kind": "event",
        "outcome": "success",
        "type": [
            "info"
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