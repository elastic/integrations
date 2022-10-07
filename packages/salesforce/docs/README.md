# Salesforce Integration

## Overview

The Salesforce integration allows you to monitor [Salesforce](https://www.salesforce.com/) instance. Salesforce provides customer relationship management service and also provides enterprise applications focused on customer service, marketing automation, analytics, and application development.

Use the Salesforce integration to get visibility into the Salesforce Org operations and hold Salesforce accountable to the Service Level Agreements. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference logs when troubleshooting an issue.

For example, if you want to check the number of successful and failed login attempts over time, you could check the same based on the ingested events or the visualization. Then you can create visualizations, alerts and troubleshoot by looking at the documents ingested in Elasticsearch.

## Data streams

The Salesforce integration collects log events using REST and Streaming API of Salesforce.

**Logs** help you keep a record of events happening in Salesforce.
Log data streams collected by the Salesforce integration include [Login](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_eventlogfile_login.htm) (using REST and Streaming API), [Logout](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_eventlogfile_logout.htm) (using REST and Streaming API), [Apex](https://developer.salesforce.com/docs/atlas.en-us.238.0.object_reference.meta/object_reference/sforce_api_objects_apexclass.htm), and [SetupAuditTrail](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_setupaudittrail.htm).

This integration uses:
- `httpjson` filebeat input to collect `login_rest`, `logout_rest`, `apex` and `setupaudittrail` events.
- `cometd` filebeat input to collect `login_stream` and `logout_stream` events.

## Compatibility

This integration has been tested against Salesforce API version `v54.0`.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Logs reference

### SetupAuditTrail

This is the `setupaudittrail` data stream. It represents changes you or other admins made in your organization's Setup area for at least the last 180 days.

An example event for `setupaudittrail` looks as following:

```json
{
    "@timestamp": "2022-08-16T09:26:38.000Z",
    "agent": {
        "ephemeral_id": "f3d13e01-7cfb-4e01-9bbd-99e08c5157b1",
        "id": "dbe82fcc-9eea-4080-91fe-9f4a6afa87ee",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.1"
    },
    "data_stream": {
        "dataset": "salesforce.setupaudittrail",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.4.0"
    },
    "elastic_agent": {
        "id": "dbe82fcc-9eea-4080-91fe-9f4a6afa87ee",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "action": "insertConnectedApplication",
        "agent_id_status": "verified",
        "created": "2022-08-16T09:26:38.000Z",
        "dataset": "salesforce.setupaudittrail",
        "id": "0Ym5j000019nwonCAA",
        "ingested": "2022-10-04T11:43:33Z",
        "kind": "event",
        "module": "salesforce",
        "original": "{\"Action\":\"insertConnectedApplication\",\"CreatedByContext\":\"Einstein\",\"CreatedById\":\"0055j000000utlPAAQ\",\"CreatedByIssuer\":null,\"CreatedDate\":\"2022-08-16T09:26:38.000+0000\",\"DelegateUser\":\"user1\",\"Display\":\"For user user@elastic.co, the User Verified Email status changed to verified\",\"Id\":\"0Ym5j000019nwonCAA\",\"ResponsibleNamespacePrefix\":\"namespaceprefix\",\"Section\":\"Connected Apps\",\"attributes\":{\"type\":\"SetupAuditTrail\",\"url\":\"/services/data/v54.0/sobjects/SetupAuditTrail/0Ym5j000019nwonCAA\"}}",
        "type": [
            "admin"
        ],
        "url": "/services/data/v54.0/sobjects/SetupAuditTrail/0Ym5j000019nwonCAA"
    },
    "input": {
        "type": "httpjson"
    },
    "salesforce": {
        "setup_audit_trail": {
            "access_mode": "rest",
            "created_by_context": "Einstein",
            "created_by_id": "0055j000000utlPAAQ",
            "delegate_user": "user1",
            "display": "For user user@elastic.co, the User Verified Email status changed to verified",
            "event_type": "SetupAuditTrail",
            "responsible_namespace_prefix": "namespaceprefix",
            "section": "Connected Apps"
        }
    },
    "tags": [
        "preserve_original_event",
        "salesforce-setupaudittrail",
        "forwarded"
    ],
    "user": {
        "id": "0055j000000utlPAAQ",
        "name": "user@elastic.co"
    }
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
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| event.url | URL linking to an external system to continue investigation of this event. This URL links to another system where in-depth investigation of the specific occurrence of this event can take place. Alert events, indicated by `event.kind:alert`, are a common use case for this field. | keyword |
| input.type | Input type. | keyword |
| salesforce.setup_audit_trail.access_mode | Type of API from which the event is collected. | keyword |
| salesforce.setup_audit_trail.created_by_context | The context under which the Setup change was made. For example, if Einstein uses cloud-to-cloud services to make a change in Setup, the value of this field is Einstein. | keyword |
| salesforce.setup_audit_trail.created_by_id | Unknown. | keyword |
| salesforce.setup_audit_trail.created_by_issuer | Reserved for future use. | keyword |
| salesforce.setup_audit_trail.delegate_user | The Login-As user who executed the action in Setup. If a Login-As user didn’t perform the action, this field is blank. This field is available in API version 35.0 and later. | keyword |
| salesforce.setup_audit_trail.display | The full description of changes made in Setup. For example, if the Action field has a value of PermSetCreate, the Display field has a value like “Created permission set MAD: with user license Salesforce.” | keyword |
| salesforce.setup_audit_trail.event_type | Event type. | keyword |
| salesforce.setup_audit_trail.responsible_namespace_prefix | Unknown. | keyword |
| salesforce.setup_audit_trail.section | The section in the Setup menu where the action occurred. For example, Manage Users or Company Profile. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
