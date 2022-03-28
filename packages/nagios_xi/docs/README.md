# Nagios XI

The Nagios XI integration is used to fetch observability data from [Nagios XI](https://www.nagios.org/documentation/) and ingest it into Elasticsearch.

## Compatibility

This module has been tested against `Nagios-XI Version: 5.8.7`

## Requirements

In order to ingest data from Nagios XI:
- You must know the host for Nagios XI, add that host while configuring the integration package.

## Logs

### Event Logs 

This is the `events` dataset.

- This dataset gives Nagios XI system event logs.

An example event for `events` looks as following:

```json
{
    "@timestamp": "2022-03-16T07:02:41.000Z",
    "agent": {
        "ephemeral_id": "4fe1ad69-f89d-4ab6-a1f1-fced88568f45",
        "id": "107183e2-010a-4007-aefa-30e7c98ce5a1",
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
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "107183e2-010a-4007-aefa-30e7c98ce5a1",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-03-17T06:34:08.396Z",
        "dataset": "nagios_xi.events",
        "ingested": "2022-03-17T06:34:09Z",
        "kind": "events",
        "module": "nagios_xi",
        "original": "{\"entry_time\":\"2022-03-16 07:02:41\",\"instance_id\":\"1\",\"logentry_data\":\"Event broker module '/usr/local/nagios/bin/ndo.so' initialized successfully.\",\"logentry_id\":\"211261\",\"logentry_type\":\"262144\"}",
        "type": "info"
    },
    "input": {
        "type": "httpjson"
    },
    "nagios_xi": {
        "event": {
            "entry_time": "2022-03-16T07:02:41.000Z",
            "instance_id": 1,
            "logentry_data": "Event broker module '/usr/local/nagios/bin/ndo.so' initialized successfully.",
            "logentry_id": 211261,
            "logentry_type": 262144
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
| nagios_xi.event.entry_time |  | keyword |
| nagios_xi.event.instance_id |  | double |
| nagios_xi.event.logentry_data |  | keyword |
| nagios_xi.event.logentry_id |  | double |
| nagios_xi.event.logentry_type |  | double |
| tags | List of keywords used to tag each event. | keyword |


## Metrics

### Host Metrics

This is the `host` dataset.

- This dataset gives Nagios XI Host Round Trip Travel Time (rta) and Packet Loss (pl) metrics.

An example event for `host` looks as following:

```json
{
    "@timestamp": "2022-03-16T07:02:42.000Z",
    "agent": {
        "ephemeral_id": "cf4ef335-820d-464b-99ac-7a534b3f409e",
        "id": "107183e2-010a-4007-aefa-30e7c98ce5a1",
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
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "107183e2-010a-4007-aefa-30e7c98ce5a1",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-03-17T06:35:56.252Z",
        "dataset": "nagios_xi.host",
        "ingested": "2022-03-17T06:35:57Z",
        "kind": "metrics",
        "module": "nagios_xi",
        "original": "{\"acknowledgement_type\":\"0\",\"action_url\":\"\",\"active_checks_enabled\":\"0\",\"address\":\"www.nagios.org\",\"check_command\":\"check_dummy!0!\\\"No data received yet.\\\"\",\"check_options\":\"0\",\"check_timeperiod_object_id\":\"71\",\"check_type\":\"1\",\"current_check_attempt\":\"1\",\"current_notification_number\":\"0\",\"current_state\":\"0\",\"display_name\":\"www.nagios.org\",\"event_handler\":\"\",\"event_handler_enabled\":\"1\",\"execution_time\":\"0\",\"failure_prediction_enabled\":\"0\",\"flap_detection_enabled\":\"1\",\"has_been_checked\":\"1\",\"host_alias\":\"www.nagios.org\",\"host_name\":\"www.nagios.org\",\"host_object_id\":\"423\",\"hoststatus_id\":\"58\",\"icon_image\":\"passiveobject.png\",\"icon_image_alt\":\"\",\"instance_id\":\"1\",\"is_flapping\":\"0\",\"last_check\":\"2020-08-04 10:07:54\",\"last_hard_state\":\"0\",\"last_hard_state_change\":\"2018-07-12 14:59:46\",\"last_notification\":\"1969-12-31 18:00:00\",\"last_state_change\":\"2015-07-13 21:09:35\",\"last_time_down\":\"1969-12-31 18:00:00\",\"last_time_unreachable\":\"1969-12-31 18:00:00\",\"last_time_up\":\"2020-08-04 10:07:54\",\"latency\":\"0\",\"long_output\":\"\",\"max_check_attempts\":\"5\",\"modified_host_attributes\":\"0\",\"next_check\":\"1969-12-31 18:00:00\",\"next_notification\":\"1969-12-31 18:00:00\",\"no_more_notifications\":\"0\",\"normal_check_interval\":\"5\",\"notes\":\"\",\"notes_url\":\"\",\"notifications_enabled\":\"1\",\"obsess_over_host\":\"1\",\"output\":\"HTTP OK: HTTP/1.1 301 Moved Permanently - 461 bytes in 0.123 second response time\",\"passive_checks_enabled\":\"1\",\"percent_state_change\":\"0\",\"perfdata\":\"time=0.122797s;;;0.000000 size=461B;;;0\",\"problem_has_been_acknowledged\":\"0\",\"process_performance_data\":\"1\",\"retry_check_interval\":\"1\",\"scheduled_downtime_depth\":\"0\",\"should_be_scheduled\":\"0\",\"state_type\":\"1\",\"status_update_time\":\"2022-03-16 07:02:42\"}",
        "type": "info"
    },
    "input": {
        "type": "httpjson"
    },
    "nagios_xi": {
        "metrics": {
            "host": {
                "check_command": "check_dummy!0!\"No data received yet.\"",
                "execution_time": 0,
                "host_name": "www.nagios.org",
                "last_check": "2020-08-04T10:07:54.000Z",
                "latency": 0,
                "next_check": "1969-12-31T18:00:00.000Z",
                "normal_check_interval": 5,
                "retry_check_interval": 1,
                "status_text": "HTTP OK: HTTP/1.1 301 Moved Permanently - 461 bytes in 0.123 second response time",
                "status_update_time": "2022-03-16T07:02:42.000Z"
            }
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
| nagios_xi.metrics.host.address |  | ip |
| nagios_xi.metrics.host.check_command |  | keyword |
| nagios_xi.metrics.host.display_name |  | keyword |
| nagios_xi.metrics.host.execution_time |  | double |
| nagios_xi.metrics.host.host_name |  | keyword |
| nagios_xi.metrics.host.last_check |  | date |
| nagios_xi.metrics.host.latency |  | double |
| nagios_xi.metrics.host.next_check |  | date |
| nagios_xi.metrics.host.normal_check_interval |  | long |
| nagios_xi.metrics.host.performance_data.pl |  | double |
| nagios_xi.metrics.host.performance_data.rta |  | double |
| nagios_xi.metrics.host.retry_check_interval |  | long |
| nagios_xi.metrics.host.status_text |  | keyword |
| nagios_xi.metrics.host.status_update_time |  | date |
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
        "ephemeral_id": "1d1bc95c-e83c-4496-80de-57b408598495",
        "id": "107183e2-010a-4007-aefa-30e7c98ce5a1",
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
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "107183e2-010a-4007-aefa-30e7c98ce5a1",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-03-17T06:37:50.605Z",
        "dataset": "nagios_xi.custom",
        "ingested": "2022-03-17T06:37:51Z",
        "kind": "metrics",
        "module": "nagios_xi",
        "original": "{\"acknowledgement_type\":\"0\",\"action_url\":\"\",\"active_checks_enabled\":\"0\",\"check_command\":\"check_dummy!0!\\\"No data received yet.\\\"\",\"check_options\":\"0\",\"check_timeperiod_object_id\":\"71\",\"check_type\":\"1\",\"current_check_attempt\":\"1\",\"current_notification_number\":\"0\",\"current_state\":\"0\",\"display_name\":\"Bandwidth Spike\",\"event_handler\":\"\",\"event_handler_enabled\":\"1\",\"execution_time\":\"0\",\"failure_prediction_enabled\":\"0\",\"flap_detection_enabled\":\"0\",\"has_been_checked\":\"1\",\"host_address\":\"www.nagios.org\",\"host_alias\":\"www.nagios.org\",\"host_name\":\"www.nagios.org\",\"host_object_id\":\"423\",\"icon_image\":\"\",\"icon_image_alt\":\"\",\"instance_id\":\"1\",\"is_flapping\":\"0\",\"last_check\":\"2020-06-17 07:12:02\",\"last_hard_state\":\"0\",\"last_hard_state_change\":\"2020-06-08 12:04:54\",\"last_notification\":\"2020-06-08 12:04:55\",\"last_state_change\":\"2020-06-08 12:04:54\",\"last_time_critical\":\"2020-06-08 12:04:54\",\"last_time_ok\":\"2020-06-17 07:12:02\",\"last_time_unknown\":\"1969-12-31 18:00:00\",\"last_time_warning\":\"2019-04-02 11:23:34\",\"latency\":\"0\",\"long_output\":\"\",\"max_check_attempts\":\"1\",\"modified_service_attributes\":\"0\",\"next_check\":\"1969-12-31 18:00:00\",\"next_notification\":\"1969-12-31 18:00:00\",\"no_more_notifications\":\"0\",\"normal_check_interval\":\"1\",\"notes\":\"\",\"notes_url\":\"\",\"notifications_enabled\":\"1\",\"obsess_over_service\":\"1\",\"output\":\"OK: 21 MB/s reported\",\"passive_checks_enabled\":\"1\",\"percent_state_change\":\"11.58\",\"perfdata\":\"bandwidth=21;80;90\",\"problem_has_been_acknowledged\":\"0\",\"process_performance_data\":\"1\",\"retry_check_interval\":\"1\",\"scheduled_downtime_depth\":\"0\",\"service_description\":\"Bandwidth Spike\",\"service_object_id\":\"999\",\"servicestatus_id\":\"996\",\"should_be_scheduled\":\"0\",\"state_type\":\"1\",\"status_update_time\":\"2022-03-17 00:02:42\"}",
        "type": "info"
    },
    "input": {
        "type": "httpjson"
    },
    "nagios_xi": {
        "metrics": {
            "service": {
                "check_command": "check_dummy!0!\"No data received yet.\"",
                "custom": {
                    "performance_data": "bandwidth=21;80;90"
                },
                "display_name": "Bandwidth Spike",
                "execution_time": 0,
                "host_name": "www.nagios.org",
                "last_check": "2020-06-17T07:12:02.000Z",
                "latency": 0,
                "next_check": "1969-12-31T18:00:00.000Z",
                "normal_check_interval": 1,
                "retry_check_interval": 1,
                "status_text": "OK: 21 MB/s reported",
                "status_update_time": "2022-03-17T00:02:42.000Z"
            }
        }
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
| nagios_xi.metrics.service.address |  | ip |
| nagios_xi.metrics.service.check_command |  | keyword |
| nagios_xi.metrics.service.current_load.load1 |  | double |
| nagios_xi.metrics.service.current_load.load15 |  | double |
| nagios_xi.metrics.service.current_load.load5 |  | double |
| nagios_xi.metrics.service.current_load.performance_data |  | keyword |
| nagios_xi.metrics.service.current_users.performance_data |  | keyword |
| nagios_xi.metrics.service.current_users.users |  | double |
| nagios_xi.metrics.service.custom.performance_data |  | keyword |
| nagios_xi.metrics.service.display_name |  | keyword |
| nagios_xi.metrics.service.execution_time |  | double |
| nagios_xi.metrics.service.host_name |  | keyword |
| nagios_xi.metrics.service.http.performance_data |  | keyword |
| nagios_xi.metrics.service.http.size |  | double |
| nagios_xi.metrics.service.http.time |  | double |
| nagios_xi.metrics.service.last_check |  | date |
| nagios_xi.metrics.service.latency |  | double |
| nagios_xi.metrics.service.next_check |  | date |
| nagios_xi.metrics.service.normal_check_interval |  | long |
| nagios_xi.metrics.service.performance_data |  | keyword |
| nagios_xi.metrics.service.ping.performance_data |  | keyword |
| nagios_xi.metrics.service.ping.pl |  | double |
| nagios_xi.metrics.service.ping.rta |  | double |
| nagios_xi.metrics.service.process.performance_data |  | keyword |
| nagios_xi.metrics.service.process.total |  | double |
| nagios_xi.metrics.service.retry_check_interval |  | long |
| nagios_xi.metrics.service.root_partition.free_space |  | double |
| nagios_xi.metrics.service.root_partition.performance_data |  | keyword |
| nagios_xi.metrics.service.root_partition.total_space |  | double |
| nagios_xi.metrics.service.root_partition.used_space |  | double |
| nagios_xi.metrics.service.ssh.performance_data |  | keyword |
| nagios_xi.metrics.service.ssh.time |  | double |
| nagios_xi.metrics.service.status_text |  | keyword |
| nagios_xi.metrics.service.status_update_time |  | date |
| nagios_xi.metrics.service.swap_usage.free_swap |  | double |
| nagios_xi.metrics.service.swap_usage.performance_data |  | keyword |
| nagios_xi.metrics.service.swap_usage.total_swap |  | double |
| nagios_xi.metrics.service.swap_usage.used_swap |  | double |
| related.ip | All of the IPs seen on your event. | ip |
| tags | List of keywords used to tag each event. | keyword |

