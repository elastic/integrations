# Nagios XI

The Nagios XI integration is used to fetch observability data from [Nagios XI](https://www.nagios.org/documentation/) and ingest it into Elasticsearch.

## Compatibility

This Integration has been tested against `Nagios-XI Version: 5.8.7`

## Requirements

In order to ingest data from Nagios XI:
- You must know the host for Nagios XI, add that host while configuring the integration package.

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
        "ephemeral_id": "dbabe791-1eaa-410d-82bf-c050c5159e45",
        "id": "d22ba4fb-aa92-45c7-a029-0da626f021b2",
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
        "id": "d22ba4fb-aa92-45c7-a029-0da626f021b2",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-03-30T17:56:04.742Z",
        "dataset": "nagios_xi.custom",
        "ingested": "2022-03-30T17:56:05Z",
        "kind": "metrics",
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
            "current_state": "0",
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
| nagios_xi.service.action_url |  | keyword |
| nagios_xi.service.active_checks_enabled |  | keyword |
| nagios_xi.service.check_command |  | keyword |
| nagios_xi.service.check_options |  | keyword |
| nagios_xi.service.check_timeperiod_object_id |  | keyword |
| nagios_xi.service.check_type |  | keyword |
| nagios_xi.service.current_check_attempt |  | keyword |
| nagios_xi.service.current_load.load1 |  | double |
| nagios_xi.service.current_load.load15 |  | double |
| nagios_xi.service.current_load.load5 |  | double |
| nagios_xi.service.current_load.performance_data |  | keyword |
| nagios_xi.service.current_notification_number |  | keyword |
| nagios_xi.service.current_state |  | keyword |
| nagios_xi.service.current_users.performance_data |  | keyword |
| nagios_xi.service.current_users.users |  | double |
| nagios_xi.service.custom.performance_data |  | keyword |
| nagios_xi.service.display_name |  | keyword |
| nagios_xi.service.event_handler |  | keyword |
| nagios_xi.service.event_handler_enabled |  | keyword |
| nagios_xi.service.execution_time |  | keyword |
| nagios_xi.service.failure_prediction_enabled |  | keyword |
| nagios_xi.service.flap_detection_enabled |  | keyword |
| nagios_xi.service.has_been_checked |  | keyword |
| nagios_xi.service.host_address |  | keyword |
| nagios_xi.service.host_alias |  | keyword |
| nagios_xi.service.host_name |  | keyword |
| nagios_xi.service.host_object_id |  | keyword |
| nagios_xi.service.http.performance_data |  | keyword |
| nagios_xi.service.http.size |  | double |
| nagios_xi.service.http.time |  | double |
| nagios_xi.service.icon_image |  | keyword |
| nagios_xi.service.icon_image_alt |  | keyword |
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
| nagios_xi.service.max_check_attempts |  | keyword |
| nagios_xi.service.modified_service_attributes |  | keyword |
| nagios_xi.service.next_check |  | date |
| nagios_xi.service.next_notification |  | date |
| nagios_xi.service.no_more_notifications |  | keyword |
| nagios_xi.service.normal_check_interval |  | keyword |
| nagios_xi.service.notes |  | keyword |
| nagios_xi.service.notes_url |  | keyword |
| nagios_xi.service.notifications_enabled |  | keyword |
| nagios_xi.service.obsess_over_service |  | keyword |
| nagios_xi.service.output |  | keyword |
| nagios_xi.service.passive_checks_enabled |  | keyword |
| nagios_xi.service.percent_state_change |  | keyword |
| nagios_xi.service.perfdata |  | keyword |
| nagios_xi.service.performance_data |  | keyword |
| nagios_xi.service.ping.performance_data |  | keyword |
| nagios_xi.service.ping.pl |  | double |
| nagios_xi.service.ping.rta |  | double |
| nagios_xi.service.problem_has_been_acknowledged |  | keyword |
| nagios_xi.service.process.performance_data |  | keyword |
| nagios_xi.service.process.total |  | double |
| nagios_xi.service.process_performance_data |  | keyword |
| nagios_xi.service.retry_check_interval |  | keyword |
| nagios_xi.service.root_partition.free_space |  | double |
| nagios_xi.service.root_partition.performance_data |  | keyword |
| nagios_xi.service.root_partition.total_space |  | double |
| nagios_xi.service.root_partition.used_space |  | double |
| nagios_xi.service.scheduled_downtime_depth |  | keyword |
| nagios_xi.service.service_description |  | keyword |
| nagios_xi.service.service_object_id |  | keyword |
| nagios_xi.service.servicestatus_id |  | keyword |
| nagios_xi.service.should_be_scheduled |  | keyword |
| nagios_xi.service.ssh.performance_data |  | keyword |
| nagios_xi.service.ssh.time |  | double |
| nagios_xi.service.state_type |  | keyword |
| nagios_xi.service.status_text |  | keyword |
| nagios_xi.service.status_update_time |  | keyword |
| nagios_xi.service.swap_usage.free_swap |  | double |
| nagios_xi.service.swap_usage.performance_data |  | keyword |
| nagios_xi.service.swap_usage.total_swap |  | double |
| nagios_xi.service.swap_usage.used_swap |  | double |
| related.ip | All of the IPs seen on your event. | ip |
| service.name | Name of the service data is collected from. The name of the service is normally user given. This allows for distributed services that run on multiple hosts to correlate the related instances based on the name. In the case of Elasticsearch the `service.name` could contain the cluster name. For Beats the `service.name` is by default a copy of the `service.type` field if no name is specified. | keyword |
| tags | List of keywords used to tag each event. | keyword |

