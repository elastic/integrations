# ForgeRock Identity Platform

ForgeRock is a modern identity platform which helps organizations radically simplify identity and access management (IAM) and identity governance and administration (IGA). The ForgeRock integration collects audit logs from the [API](https://backstage.forgerock.com/knowledge/kb/article/a37739488).

### Configuration

TBD

### Example event


An example event for ForgeRock looks as following:

```json
{
    "@timestamp": "2022-11-06T18:16:43.813Z",
    "agent": {
        "ephemeral_id": "a094e100-47c9-454c-864b-83b7c82a0ac6",
        "id": "04d7a3b3-051e-4f00-9185-a836c4c49e52",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.3.2"
    },
    "data_stream": {
        "dataset": "forgerock.am_activity",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.4.0"
    },
    "elastic_agent": {
        "id": "04d7a3b3-051e-4f00-9185-a836c4c49e52",
        "snapshot": false,
        "version": "8.3.2"
    },
    "event": {
        "action": "AM-SESSION-IDLE_TIMED_OUT",
        "agent_id_status": "verified",
        "created": "2022-11-14T19:49:14.594Z",
        "dataset": "forgerock.audit",
        "id": "688b24d9-968e-4a20-b471-9bd78f1e46ec-79599",
        "ingested": "2022-11-14T19:49:18Z",
        "original": "{\"payload\":{\"_id\":\"688b24d9-968e-4a20-b471-9bd78f1e46ec-79599\",\"component\":\"Session\",\"eventName\":\"AM-SESSION-IDLE_TIMED_OUT\",\"level\":\"INFO\",\"objectId\":\"688b24d9-968e-4a20-b471-9bd78f1e46ec-13901\",\"operation\":\"DELETE\",\"realm\":\"/\",\"runAs\":\"\",\"source\":\"audit\",\"timestamp\":\"2022-11-06T18:16:43.813Z\",\"topic\":\"activity\",\"trackingIds\":[\"688b24d9-968e-4a20-b471-9bd78f1e46ec-13901\"],\"transactionId\":\"688b24d9-968e-4a20-b471-9bd78f1e46ec-1\",\"userId\":\"id=d7cd65bf-743c-4753-a78f-a20daae7e3bf,ou=user,ou=am-config\"},\"source\":\"am-activity\",\"timestamp\":\"2022-11-06T18:16:43.814159262Z\",\"type\":\"application/json\"}",
        "reason": "DELETE"
    },
    "forgerock": {
        "level": "INFO",
        "objectId": "688b24d9-968e-4a20-b471-9bd78f1e46ec-13901",
        "realm": "/",
        "source": "audit",
        "topic": "activity",
        "trackingIds": [
            "688b24d9-968e-4a20-b471-9bd78f1e46ec-13901"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "observer": {
        "vendor": "ForgeRock Identity Platform"
    },
    "service": {
        "name": "Session"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "forgerock-audit"
    ],
    "transaction": {
        "id": "688b24d9-968e-4a20-b471-9bd78f1e46ec-1"
    },
    "user": {
        "effective": {
            "id": ""
        },
        "id": "id=d7cd65bf-743c-4753-a78f-a20daae7e3bf,ou=user,ou=am-config"
    }
}
```

**Exported fields**

**Exported fields**

(no fields available)
