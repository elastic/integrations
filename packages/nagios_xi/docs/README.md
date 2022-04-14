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


## Metrics

### Host Metrics

This is the `host` data stream.

- This data stream gives Nagios XI Host Round Trip Travel Time (rta) and Packet Loss (pl) metrics.

An example event for `host` looks as following:

```json
{
    "@timestamp": "2022-03-16T07:02:42.000Z",
    "agent": {
        "ephemeral_id": "064e8b16-0813-4bb8-b9dc-c9dbf70039ab",
        "id": "bca41c71-7143-4fcb-b873-756d7d08c621",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "nagios_xi.host",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.1.0"
    },
    "elastic_agent": {
        "id": "bca41c71-7143-4fcb-b873-756d7d08c621",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-04-04T05:37:40.920Z",
        "dataset": "nagios_xi.host",
        "ingested": "2022-04-04T05:37:41Z",
        "kind": "metrics",
        "module": "nagios_xi",
        "original": "{\"acknowledgement_type\":\"0\",\"action_url\":\"\",\"active_checks_enabled\":\"0\",\"address\":\"www.nagios.org\",\"check_command\":\"check_dummy!0!\\\"No data received yet.\\\"\",\"check_options\":\"0\",\"check_timeperiod_object_id\":\"71\",\"check_type\":\"1\",\"current_check_attempt\":\"1\",\"current_notification_number\":\"0\",\"current_state\":\"0\",\"display_name\":\"www.nagios.org\",\"event_handler\":\"\",\"event_handler_enabled\":\"1\",\"execution_time\":\"0\",\"failure_prediction_enabled\":\"0\",\"flap_detection_enabled\":\"1\",\"has_been_checked\":\"1\",\"host_alias\":\"www.nagios.org\",\"host_name\":\"www.nagios.org\",\"host_object_id\":\"423\",\"hoststatus_id\":\"58\",\"icon_image\":\"passiveobject.png\",\"icon_image_alt\":\"\",\"instance_id\":\"1\",\"is_flapping\":\"0\",\"last_check\":\"2020-08-04 10:07:54\",\"last_hard_state\":\"0\",\"last_hard_state_change\":\"2018-07-12 14:59:46\",\"last_notification\":\"1969-12-31 18:00:00\",\"last_state_change\":\"2015-07-13 21:09:35\",\"last_time_down\":\"1969-12-31 18:00:00\",\"last_time_unreachable\":\"1969-12-31 18:00:00\",\"last_time_up\":\"2020-08-04 10:07:54\",\"latency\":\"0\",\"long_output\":\"\",\"max_check_attempts\":\"5\",\"modified_host_attributes\":\"0\",\"next_check\":\"1969-12-31 18:00:00\",\"next_notification\":\"1969-12-31 18:00:00\",\"no_more_notifications\":\"0\",\"normal_check_interval\":\"5\",\"notes\":\"\",\"notes_url\":\"\",\"notifications_enabled\":\"1\",\"obsess_over_host\":\"1\",\"output\":\"HTTP OK: HTTP/1.1 301 Moved Permanently - 461 bytes in 0.123 second response time\",\"passive_checks_enabled\":\"1\",\"percent_state_change\":\"0\",\"perfdata\":\"time=0.122797s;;;0.000000 size=461B;;;0\",\"problem_has_been_acknowledged\":\"0\",\"process_performance_data\":\"1\",\"retry_check_interval\":\"1\",\"scheduled_downtime_depth\":\"0\",\"should_be_scheduled\":\"0\",\"state_type\":\"1\",\"status_update_time\":\"2022-03-16 07:02:42\"}",
        "type": "info"
    },
    "input": {
        "type": "httpjson"
    },
    "nagios_xi": {
        "host": {
            "acknowledgement_type": "0",
            "active_checks_enabled": "0",
            "address": "www.nagios.org",
            "check_command": "check_dummy!0!\"No data received yet.\"",
            "check_options": "0",
            "check_timeperiod_object_id": "71",
            "check_type": "1",
            "current_check_attempt": "1",
            "current_notification_number": "0",
            "current_state": "0",
            "display_name": "www.nagios.org",
            "event_handler_enabled": "1",
            "execution_time": 0,
            "failure_prediction_enabled": "0",
            "flap_detection_enabled": "1",
            "has_been_checked": "1",
            "host_alias": "www.nagios.org",
            "host_name": "www.nagios.org",
            "host_object_id": "423",
            "hoststatus_id": "58",
            "icon_image": "passiveobject.png",
            "instance_id": "1",
            "is_flapping": "0",
            "last_check": "2020-08-04T10:07:54.000Z",
            "last_hard_state": "0",
            "last_hard_state_change": "2018-07-12T14:59:46.000Z",
            "last_notification": "1969-12-31T18:00:00.000Z",
            "last_time_down": "1969-12-31T18:00:00.000Z",
            "last_time_unreachable": "1969-12-31T18:00:00.000Z",
            "last_time_up": "2020-08-04T10:07:54.000Z",
            "latency": 0,
            "max_check_attempts": "5",
            "modified_host_attributes": "0",
            "next_check": "1969-12-31T18:00:00.000Z",
            "next_notification": "1969-12-31T18:00:00.000Z",
            "no_more_notifications": "0",
            "normal_check_interval": 5,
            "notifications_enabled": "1",
            "obsess_over_host": "1",
            "output": "HTTP OK: HTTP/1.1 301 Moved Permanently - 461 bytes in 0.123 second response time",
            "passive_checks_enabled": "1",
            "percent_state_change": "0",
            "performance_data": {
                "size": 461,
                "time": 0.122797
            },
            "problem_has_been_acknowledged": "0",
            "process_performance_data": "1",
            "retry_check_interval": 1,
            "scheduled_downtime_depth": "0",
            "should_be_scheduled": "0",
            "state_type": "1",
            "status_update_time": "2022-03-16T07:02:42.000Z"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "nagios_xi-host"
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
| host.ip | Host ip addresses. | ip |
| input.type | Type of Filebeat input. | keyword |
| nagios_xi.host.acknowledgement_type |  | keyword |
| nagios_xi.host.action_url | This is used to define an optional URL that can be used to provide more actions to be performed on the host. | keyword |
| nagios_xi.host.active_checks_enabled | This is used to determine whether or not active checks (either regularly scheduled or on-demand) of this host are enabled. Values=\> 0 = disable active host checks, 1 = enable active host checks (default). | keyword |
| nagios_xi.host.address | This is used to define the address of the host. Normally, this is an IP address, although it could really be anything user want (so long as it can be used to check the status of the host). | keyword |
| nagios_xi.host.check_command | This is used to specify the short name of the command that should be used to check if the host is up or down. Typically, this command would try and ping the host to see if it is "alive". | keyword |
| nagios_xi.host.check_options |  | keyword |
| nagios_xi.host.check_timeperiod_object_id |  | keyword |
| nagios_xi.host.check_type |  | keyword |
| nagios_xi.host.current_check_attempt |  | keyword |
| nagios_xi.host.current_notification_number |  | keyword |
| nagios_xi.host.current_state | This is used to check current status of host. | keyword |
| nagios_xi.host.display_name | This is used to define an alternate name that should be displayed in the web interface for this host. | keyword |
| nagios_xi.host.event_handler | This is used to specify the short name of the command that should be run whenever a change in the state of the host is detected (i.e. whenever it goes down or recovers). | keyword |
| nagios_xi.host.event_handler_enabled | This is used to determine whether or not the event handler for this host is enabled. Values=\> 0 = disable host event handler, 1 = enable host event handler. | keyword |
| nagios_xi.host.execution_time |  | double |
| nagios_xi.host.failure_prediction_enabled |  | keyword |
| nagios_xi.host.flap_detection_enabled | This is used to determine whether or not flap detection is enabled for this host. More information on flap detection can be found here. Values=\> 0 = disable host flap detection, 1 = enable host flap detection. | keyword |
| nagios_xi.host.has_been_checked |  | keyword |
| nagios_xi.host.host_alias | This is used to define a longer name or description used to identify the host. | keyword |
| nagios_xi.host.host_name | This is used to define a short name used to identify the host. It is used in host group and service definitions to reference this particular host. | keyword |
| nagios_xi.host.host_object_id |  | keyword |
| nagios_xi.host.hoststatus_id |  | keyword |
| nagios_xi.host.icon_image | This variable is used to define the name of a GIF, PNG, or JPG image that should be associated with this host. This image will be displayed in the various places in the CGIs. | keyword |
| nagios_xi.host.icon_image_alt | This variable is used to define an optional string that is used in the ALT tag of the image specified by the \<icon_image\> argument. | keyword |
| nagios_xi.host.instance_id |  | keyword |
| nagios_xi.host.is_flapping |  | keyword |
| nagios_xi.host.last_check |  | date |
| nagios_xi.host.last_hard_state |  | keyword |
| nagios_xi.host.last_hard_state_change |  | date |
| nagios_xi.host.last_notification |  | date |
| nagios_xi.host.last_state_change |  | date |
| nagios_xi.host.last_time_down |  | date |
| nagios_xi.host.last_time_unreachable |  | date |
| nagios_xi.host.last_time_up |  | date |
| nagios_xi.host.latency |  | double |
| nagios_xi.host.long_output |  | keyword |
| nagios_xi.host.max_check_attempts | This is used to define the number of times that Nagios will retry the host check command if it returns any state other than an OK state. | keyword |
| nagios_xi.host.modified_host_attributes |  | keyword |
| nagios_xi.host.next_check |  | date |
| nagios_xi.host.next_notification |  | date |
| nagios_xi.host.no_more_notifications |  | keyword |
| nagios_xi.host.normal_check_interval | This is used to define the number of "time units" between regularly scheduled checks of the host. | long |
| nagios_xi.host.notes | This is used to define an optional string of notes pertaining to the host. | keyword |
| nagios_xi.host.notes_url | This variable is used to define an optional URL that can be used to provide more information about the host. | keyword |
| nagios_xi.host.notifications_enabled | This is used to determine whether or not notifications for this host are enabled. Values=\> 0 = disable host notifications, 1 = enable host notifications. | keyword |
| nagios_xi.host.obsess_over_host | This determines whether or not checks for the host will be "obsessed" over using the ochp_command. | keyword |
| nagios_xi.host.output |  | keyword |
| nagios_xi.host.passive_checks_enabled | This is used to determine whether or not passive checks are enabled for this host. Values=\> 0 = disable passive host checks, 1 = enable passive host checks (default). | keyword |
| nagios_xi.host.percent_state_change |  | keyword |
| nagios_xi.host.perfdata | This is used to show exact outcome of check command. | keyword |
| nagios_xi.host.performance_data.pl | This shows Packet Loss for current host. | double |
| nagios_xi.host.performance_data.rta | This shows Round Trip Around for current host. | double |
| nagios_xi.host.performance_data.size | This shows Request Size for current host. | double |
| nagios_xi.host.performance_data.time | This shows Time taken while request for current host. | double |
| nagios_xi.host.problem_has_been_acknowledged |  | keyword |
| nagios_xi.host.process_performance_data | This is used to determine whether or not the processing of performance data is enabled for this host. Values=\> 0 = disable performance data processing, 1 = enable performance data processing. | keyword |
| nagios_xi.host.retry_check_interval | This is used to define the number of "time units" to wait before scheduling a re-check of the hosts. Hosts are rescheduled at the retry interval when they have changed to a non-UP state. | long |
| nagios_xi.host.scheduled_downtime_depth |  | keyword |
| nagios_xi.host.should_be_scheduled |  | keyword |
| nagios_xi.host.state_type |  | keyword |
| nagios_xi.host.status_update_time |  | date |
| related.ip | All of the IPs seen on your event. | ip |
| tags | List of keywords used to tag each event. | keyword |

