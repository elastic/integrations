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
        "ephemeral_id": "51b119f6-cf3c-4fe1-ba07-4f8194106cda",
        "id": "98cccf9b-3d95-4b93-b4dc-472035898e0f",
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
        "id": "98cccf9b-3d95-4b93-b4dc-472035898e0f",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-05-09T07:14:09.873Z",
        "dataset": "nagios_xi.events",
        "ingested": "2022-05-09T07:14:10Z",
        "kind": "event",
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
        "ephemeral_id": "a8300647-0cfb-4d68-8f1f-ac4fbf423edf",
        "id": "98cccf9b-3d95-4b93-b4dc-472035898e0f",
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
        "id": "98cccf9b-3d95-4b93-b4dc-472035898e0f",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-05-09T07:14:52.511Z",
        "dataset": "nagios_xi.host",
        "ingested": "2022-05-09T07:14:53Z",
        "kind": "metric",
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
            "current_state": "Up/Pending",
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


### Service Metrics

This is the `service` dataset.

- This dataset gives Nagios XI services current load, current users, ping, http, ssh, root partition, swap users and total processes metrics by default.
- If the user enters a display name of a custom check command, then the integration would also fetch and index that but not parse/perform additional extractions. Additionally, the user can provide a custom processor through the configuration page if they are interested in parsing it
- If the user enters the host name and no display name, then similar to 1, the integration will fetch all the services from that host and index, but only parse the default one i.e the 8 services. The user can provide a custom processor in this case
- If the user enters both the host name and the display name, then the integration would only fetch those services with the entered display name and only from the entered hosts. It is not possible to fetch 1 service from host1 and another service from host2 in this case as it will fetch all the services from all the hosts that are configured

An example event for `service` looks as following:

```json
{
    "@timestamp": "2022-03-17T00:02:42.000Z",
    "agent": {
        "ephemeral_id": "d0a9190e-82f3-40f0-956b-9c37209e3203",
        "id": "98cccf9b-3d95-4b93-b4dc-472035898e0f",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "nagios_xi.service",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.1.0"
    },
    "elastic_agent": {
        "id": "98cccf9b-3d95-4b93-b4dc-472035898e0f",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-05-09T07:15:37.790Z",
        "dataset": "nagios_xi.custom",
        "ingested": "2022-05-09T07:15:38Z",
        "kind": "metric",
        "module": "nagios_xi",
        "original": "{\"acknowledgement_type\":\"0\",\"action_url\":\"\",\"active_checks_enabled\":\"0\",\"check_command\":\"check_dummy!0!\\\"No data received yet.\\\"\",\"check_options\":\"0\",\"check_timeperiod_object_id\":\"71\",\"check_type\":\"1\",\"current_check_attempt\":\"1\",\"current_notification_number\":\"0\",\"current_state\":\"0\",\"display_name\":\"Bandwidth Spike\",\"event_handler\":\"\",\"event_handler_enabled\":\"1\",\"execution_time\":\"0\",\"failure_prediction_enabled\":\"0\",\"flap_detection_enabled\":\"0\",\"has_been_checked\":\"1\",\"host_address\":\"www.nagios.org\",\"host_alias\":\"www.nagios.org\",\"host_name\":\"www.nagios.org\",\"host_object_id\":\"423\",\"icon_image\":\"\",\"icon_image_alt\":\"\",\"instance_id\":\"1\",\"is_flapping\":\"0\",\"last_check\":\"2020-06-17 07:12:02\",\"last_hard_state\":\"0\",\"last_hard_state_change\":\"2020-06-08 12:04:54\",\"last_notification\":\"2020-06-08 12:04:55\",\"last_state_change\":\"2020-06-08 12:04:54\",\"last_time_critical\":\"2020-06-08 12:04:54\",\"last_time_ok\":\"2020-06-17 07:12:02\",\"last_time_unknown\":\"1969-12-31 18:00:00\",\"last_time_warning\":\"2019-04-02 11:23:34\",\"latency\":\"0\",\"long_output\":\"\",\"max_check_attempts\":\"1\",\"modified_service_attributes\":\"0\",\"next_check\":\"1969-12-31 18:00:00\",\"next_notification\":\"1969-12-31 18:00:00\",\"no_more_notifications\":\"0\",\"normal_check_interval\":\"1\",\"notes\":\"\",\"notes_url\":\"\",\"notifications_enabled\":\"1\",\"obsess_over_service\":\"1\",\"output\":\"OK: 21 MB/s reported\",\"passive_checks_enabled\":\"1\",\"percent_state_change\":\"11.58\",\"perfdata\":\"bandwidth=21;80;90\",\"problem_has_been_acknowledged\":\"0\",\"process_performance_data\":\"1\",\"retry_check_interval\":\"1\",\"scheduled_downtime_depth\":\"0\",\"service_description\":\"Bandwidth Spike\",\"service_object_id\":\"999\",\"servicestatus_id\":\"996\",\"should_be_scheduled\":\"0\",\"state_type\":\"1\",\"status_update_time\":\"2022-03-17 00:02:42\"}",
        "type": "info"
    },
    "input": {
        "type": "httpjson"
    },
    "nagios_xi": {
        "service": {
            "acknowledgement_type": "0",
            "active_checks_enabled": "0",
            "check_command": "check_dummy!0!\"No data received yet.\"",
            "check_options": "0",
            "check_timeperiod_object_id": "71",
            "check_type": "1",
            "current_check_attempt": "1",
            "current_notification_number": "0",
            "current_state": "Up/Pending",
            "custom": {
                "performance_data": "bandwidth=21;80;90"
            },
            "event_handler_enabled": "1",
            "execution_time": 0,
            "failure_prediction_enabled": "0",
            "flap_detection_enabled": "0",
            "has_been_checked": "1",
            "host_address": "www.nagios.org",
            "host_alias": "www.nagios.org",
            "host_name": "www.nagios.org",
            "host_object_id": "423",
            "instance_id": "1",
            "is_flapping": "0",
            "last_check": "2020-06-17T07:12:02.000Z",
            "last_hard_state": "0",
            "last_hard_state_change": "2020-06-08T12:04:54.000Z",
            "last_notification": "2020-06-08T12:04:55.000Z",
            "last_state_change": "2020-06-08T12:04:54.000Z",
            "last_time_critical": "2020-06-08T12:04:54.000Z",
            "last_time_ok": "2020-06-17T07:12:02.000Z",
            "last_time_unknown": "1969-12-31T18:00:00.000Z",
            "last_time_warning": "2019-04-02T11:23:34.000Z",
            "latency": 0,
            "max_check_attempts": "1",
            "modified_service_attributes": "0",
            "next_check": "1969-12-31T18:00:00.000Z",
            "next_notification": "1969-12-31T18:00:00.000Z",
            "no_more_notifications": "0",
            "normal_check_interval": 1,
            "notifications_enabled": "1",
            "obsess_over_service": "1",
            "output": "OK: 21 MB/s reported",
            "passive_checks_enabled": "1",
            "percent_state_change": "11.58",
            "problem_has_been_acknowledged": "0",
            "process_performance_data": "1",
            "retry_check_interval": 1,
            "scheduled_downtime_depth": "0",
            "service_description": "Bandwidth Spike",
            "service_object_id": "999",
            "servicestatus_id": "996",
            "should_be_scheduled": "0",
            "state_type": "1",
            "status_update_time": "2022-03-17T00:02:42.000Z"
        }
    },
    "service": {
        "name": "Bandwidth Spike"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "nagios_xi-service"
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
| nagios_xi.service.acknowledgement_type |  | keyword |
| nagios_xi.service.action_url | This is used to define an optional URL that can be used to provide more actions to be performed on the host. If you specify an URL, you will see a red "splat" icon in the CGIs (when you are viewing host information) that links to the URL you specify here. Any valid URL can be used. If you plan on using relative paths, the base path will the the same as what is used to access the CGIs (i.e. /cgi-bin/nagios/). | keyword |
| nagios_xi.service.active_checks_enabled | This is used to determine whether or not active checks (either regularly scheduled or on-demand) of this host are enabled. Values=\> 0 = disable active host checks, 1 = enable active host checks (default). | keyword |
| nagios_xi.service.check_command | This is used to specify the short name of the command that should be used to check if the host is up or down. Typically, this command would try and ping the host to see if it is "alive". The command must return a status of OK (0) or Nagios will assume the host is down. If you leave this argument blank, the host will not be actively checked. Thus, Nagios will likely always assume the host is up (it may show up as being in a "PENDING" state in the web interface). This is useful if you are monitoring printers or other devices that are frequently turned off. The maximum amount of time that the notification command can run is controlled by the host_check_timeout option. | keyword |
| nagios_xi.service.check_options |  | keyword |
| nagios_xi.service.check_timeperiod_object_id |  | keyword |
| nagios_xi.service.check_type |  | keyword |
| nagios_xi.service.current_check_attempt |  | keyword |
| nagios_xi.service.current_load.load1 | Current Load in 1m. | double |
| nagios_xi.service.current_load.load15 | Current Load in 15m. | double |
| nagios_xi.service.current_load.load5 | Current Load in 5m. | double |
| nagios_xi.service.current_load.performance_data | Exact output of check_command. | keyword |
| nagios_xi.service.current_notification_number |  | keyword |
| nagios_xi.service.current_state |  | keyword |
| nagios_xi.service.current_users.performance_data | Exact output of check_command. | keyword |
| nagios_xi.service.current_users.users | Current Users in host. | double |
| nagios_xi.service.custom.performance_data | Exact output of check_command. | keyword |
| nagios_xi.service.display_name | This is used to define an alternate name that should be displayed in the web interface for this host. If not specified, this defaults to the value you specify for the host_name directive. | keyword |
| nagios_xi.service.event_handler | This is used to specify the short name of the command that should be run whenever a change in the state of the host is detected (i.e. whenever it goes down or recovers). Read the documentation on event handlers for a more detailed explanation of how to write scripts for handling events. The maximum amount of time that the event handler command can run is controlled by the event_handler_timeout option. | keyword |
| nagios_xi.service.event_handler_enabled | This is used to determine whether or not the event handler for this host is enabled. Values=\> 0 = disable host event handler, 1 = enable host event handler. | keyword |
| nagios_xi.service.execution_time |  | double |
| nagios_xi.service.failure_prediction_enabled |  | keyword |
| nagios_xi.service.flap_detection_enabled | This is used to determine whether or not flap detection is enabled for this host. More information on flap detection can be found here. Values=\> 0 = disable host flap detection, 1 = enable host flap detection. | keyword |
| nagios_xi.service.has_been_checked |  | keyword |
| nagios_xi.service.host_address |  | keyword |
| nagios_xi.service.host_alias |  | keyword |
| nagios_xi.service.host_name |  | keyword |
| nagios_xi.service.host_object_id |  | keyword |
| nagios_xi.service.http.performance_data | Exact output of check_command. | keyword |
| nagios_xi.service.http.size | Http byte size while request to host. | double |
| nagios_xi.service.http.time | Http Time taken while request to host. | double |
| nagios_xi.service.icon_image | This variable is used to define the name of a GIF, PNG, or JPG image that should be associated with this host. This image will be displayed in the various places in the CGIs. The image will look best if it is 40x40 pixels in size. Images for hosts are assumed to be in the logos/ subdirectory in your HTML images directory (i.e. /usr/local/nagios/share/images/logos). | keyword |
| nagios_xi.service.icon_image_alt | This variable is used to define an optional string that is used in the ALT tag of the image specified by the \<icon_image\> argument. | keyword |
| nagios_xi.service.instance_id |  | keyword |
| nagios_xi.service.is_flapping |  | keyword |
| nagios_xi.service.last_check |  | date |
| nagios_xi.service.last_hard_state |  | keyword |
| nagios_xi.service.last_hard_state_change |  | date |
| nagios_xi.service.last_notification |  | date |
| nagios_xi.service.last_state_change |  | date |
| nagios_xi.service.last_time_critical |  | date |
| nagios_xi.service.last_time_ok |  | date |
| nagios_xi.service.last_time_unknown |  | date |
| nagios_xi.service.last_time_warning |  | date |
| nagios_xi.service.latency |  | double |
| nagios_xi.service.long_output |  | keyword |
| nagios_xi.service.max_check_attempts | This is used to define the number of times that Nagios will retry the host check command if it returns any state other than an OK state. Setting this value to 1 will cause Nagios to generate an alert without retrying the host check. | keyword |
| nagios_xi.service.modified_service_attributes |  | keyword |
| nagios_xi.service.next_check |  | date |
| nagios_xi.service.next_notification |  | date |
| nagios_xi.service.no_more_notifications |  | keyword |
| nagios_xi.service.normal_check_interval | This is used to define the number of "time units" between regularly scheduled checks of the host. Unless you've changed the interval_length from the default value of 60, this number will mean minutes. More information on this value can be found in the check scheduling documentation. | long |
| nagios_xi.service.notes | This is used to define an optional string of notes pertaining to the host. If you specify a note here, you will see the it in the extended information CGI (when you are viewing information about the specified host). | keyword |
| nagios_xi.service.notes_url | This variable is used to define an optional URL that can be used to provide more information about the host. If you specify an URL, you will see a red folder icon in the CGIs (when you are viewing host information) that links to the URL you specify here. Any valid URL can be used. If you plan on using relative paths, the base path will the the same as what is used to access the CGIs (i.e. /cgi-bin/nagios/). This can be very useful if you want to make detailed information on the host, emergency contact methods, etc. available to other support staff. | keyword |
| nagios_xi.service.notifications_enabled | This is used to determine whether or not notifications for this host are enabled. Values=\> 0 = disable host notifications, 1 = enable host notifications. | keyword |
| nagios_xi.service.obsess_over_service |  | keyword |
| nagios_xi.service.output |  | keyword |
| nagios_xi.service.passive_checks_enabled | This is used to determine whether or not passive checks are enabled for this host. Values=\> 0 = disable passive host checks, 1 = enable passive host checks (default). | keyword |
| nagios_xi.service.percent_state_change |  | keyword |
| nagios_xi.service.perfdata | This is used to determine whether or not the processing of performance data is enabled for this host. Values=\> 0 = disable performance data processing, 1 = enable performance data processing. | keyword |
| nagios_xi.service.ping.performance_data | Exact output of check_command. | keyword |
| nagios_xi.service.ping.pl | Packet Loss while ping to host. | double |
| nagios_xi.service.ping.rta | Round Trip Around while ping to host. | double |
| nagios_xi.service.problem_has_been_acknowledged |  | keyword |
| nagios_xi.service.process.performance_data | Exact output of check_command. | keyword |
| nagios_xi.service.process.total | Total processes in host. | double |
| nagios_xi.service.process_performance_data | This is used to determine whether or not the processing of performance data is enabled for this host. Values=\> 0 = disable performance data processing, 1 = enable performance data processing. | keyword |
| nagios_xi.service.retry_check_interval | This is used to define the number of "time units" to wait before scheduling a re-check of the hosts. Hosts are rescheduled at the retry interval when they have changed to a non-UP state. Once the host has been retried max_check_attempts times without a change in its status, it will revert to being scheduled at its "normal" rate as defined by the check_interval value. Unless you've changed the interval_length from the default value of 60, this number will mean minutes. More information on this value can be found in the check scheduling documentation. | long |
| nagios_xi.service.root_partition.free_space | Free Space in host. | double |
| nagios_xi.service.root_partition.performance_data | Exact output of check_command. | keyword |
| nagios_xi.service.root_partition.total_space | Total Space in host. | double |
| nagios_xi.service.root_partition.used_space | Used space in host. | double |
| nagios_xi.service.scheduled_downtime_depth |  | keyword |
| nagios_xi.service.service_description |  | keyword |
| nagios_xi.service.service_object_id |  | keyword |
| nagios_xi.service.servicestatus_id |  | keyword |
| nagios_xi.service.should_be_scheduled |  | keyword |
| nagios_xi.service.ssh.performance_data | Exact output of check_command. | keyword |
| nagios_xi.service.ssh.time | SSH time taken for host. | double |
| nagios_xi.service.state_type |  | keyword |
| nagios_xi.service.status_text |  | keyword |
| nagios_xi.service.status_update_time |  | date |
| nagios_xi.service.swap_usage.free_swap | Free swap usage for host. | double |
| nagios_xi.service.swap_usage.performance_data | Exact output of check_command. | keyword |
| nagios_xi.service.swap_usage.total_swap | Total swap usage for host. | double |
| nagios_xi.service.swap_usage.used_swap | Used swap usage for host. | double |
| related.ip | All of the IPs seen on your event. | ip |
| service.name | Name of the service data is collected from. The name of the service is normally user given. This allows for distributed services that run on multiple hosts to correlate the related instances based on the name. In the case of Elasticsearch the `service.name` could contain the cluster name. For Beats the `service.name` is by default a copy of the `service.type` field if no name is specified. | keyword |
| tags | List of keywords used to tag each event. | keyword |

