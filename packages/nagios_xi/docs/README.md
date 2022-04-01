# Nagios XI

The Nagios XI integration is used to fetch observability data from [Nagios XI](https://www.nagios.org/documentation/) and ingest it into Elasticsearch.

## Compatibility

This integration has been tested against `Nagios-XI Version: 5.8.7`

## Requirements

In order to ingest data from Nagios XI:
- You must know the host for Nagios XI, add that host while configuring the integration package.

## Logs

### Event Logs 

This is the `events` data stream.

- This data stream gives Nagios XI system event logs.

An example event for `events` looks as following:

```json
{
    "@timestamp": "2022-03-16T07:02:41.000Z",
    "agent": {
        "ephemeral_id": "71ba3a4e-68fd-4101-b854-c8ff47d99fb7",
        "id": "aba80e42-0c9f-4556-9f76-9db14503b734",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "nagios_xi.events",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.1.0"
    },
    "elastic_agent": {
        "id": "aba80e42-0c9f-4556-9f76-9db14503b734",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-04-01T09:37:09.708Z",
        "dataset": "nagios_xi.events",
        "ingested": "2022-04-01T09:37:10Z",
        "kind": "events",
        "module": "nagios_xi",
        "original": "{\"entry_time\":\"2022-03-16 07:02:41\",\"instance_id\":\"1\",\"logentry_data\":\"Event broker module '/usr/local/nagios/bin/ndo.so' initialized successfully.\",\"logentry_id\":\"211261\",\"logentry_type\":\"262144\"}",
        "type": "info"
    },
    "input": {
        "type": "httpjson"
    },
    "message": "Event broker module '/usr/local/nagios/bin/ndo.so' initialized successfully.",
    "nagios_xi": {
        "event": {
            "entry_time": "2022-03-16T07:02:41.000Z",
            "instance_id": 1,
            "logentry": {
                "id": 211261,
                "type": 262144
            }
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "nagios_xi-events"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| input.type | Type of Filebeat input. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| nagios_xi.event.entry_time | Log entry time | keyword |
| nagios_xi.event.instance_id | Instace ID of current instance | double |
| nagios_xi.event.logentry.id | Logentry ID | double |
| nagios_xi.event.logentry.type | Logentry type | double |
| tags | List of keywords used to tag each event. | keyword |

