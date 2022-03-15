# Nagios

The Nagios integration is used to fetch observability data from [Nagios](https://www.nagios.org/documentation/) and ingest it into Elasticsearch.

## Compatibility

This module has been tested against `nagios-xi Version: 5.8.7`

## Requirements

In order to ingest data from Nagios:
- You must know the host for Nagios, add that host while configuring the integration package.

## Logs

### Logs logs

This is the `logs` dataset.

- This dataset gives Nagios system logs.

An example event for `logs` looks as following:

```json
{
    "@timestamp": "2022-03-11T15:51:46.000Z",
    "agent": {
        "ephemeral_id": "449b2c8b-40a3-4fa7-b717-8bfc460663d7",
        "id": "01244f10-29f9-4ebb-b2bd-3cea353113de",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "nagios.logs",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "01244f10-29f9-4ebb-b2bd-3cea353113de",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-03-14T09:15:31.383Z",
        "dataset": "nagios.logs",
        "ingested": "2022-03-14T09:15:32Z",
        "kind": "logs",
        "module": "nagios",
        "original": "{\"entry_time\":\"2022-03-11 15:51:46\",\"instance_id\":\"1\",\"logentry_data\":\"SERVICE NOTIFICATION: nagiosadmin;localhost;Service Status - ntpd;WARNING;xi_service_notification_handler;ntpd dead but pid file exists\",\"logentry_type\":\"1048576\"}",
        "type": "info"
    },
    "input": {
        "type": "httpjson"
    },
    "nagios": {
        "log": {
            "entry_time": "2022-03-11T15:51:46.000Z",
            "instance_id": 1,
            "logentry_data": "SERVICE NOTIFICATION: nagiosadmin;localhost;Service Status - ntpd;WARNING;xi_service_notification_handler;ntpd dead but pid file exists",
            "logentry_type": 1048576
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "nagios-logs"
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
| nagios.log.entry_time |  | keyword |
| nagios.log.instance_id |  | double |
| nagios.log.logentry_data |  | keyword |
| nagios.log.logentry_type |  | double |
| tags | List of keywords used to tag each event. | keyword |


## Metrics

### Host Metrics

This is the `host` dataset.

- This dataset gives Host Round Trip Travel Time (rta) and Packet Loss (pl) metrics.

An example event for `host` looks as following:

```json
{
    "@timestamp": "2022-03-12T15:44:20.000Z",
    "agent": {
        "ephemeral_id": "a43c3c69-fac3-4c12-a79d-dd22ae401c5e",
        "id": "01244f10-29f9-4ebb-b2bd-3cea353113de",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "nagios.host",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "01244f10-29f9-4ebb-b2bd-3cea353113de",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-03-14T09:13:46.258Z",
        "dataset": "nagios.host",
        "ingested": "2022-03-14T09:13:47Z",
        "kind": "metrics",
        "module": "nagios",
        "original": "{\"@attributes\":{\"id\":\"11\"},\"acknowledgement_type\":\"0\",\"active_checks_enabled\":\"1\",\"address\":\"10.0.6.127\",\"alias\":\"10.0.6.127\",\"check_command\":\"\",\"check_timeperiod_id\":\"12\",\"check_type\":\"0\",\"current_check_attempt\":\"1\",\"current_notification_number\":\"0\",\"current_state\":\"0\",\"display_name\":\"10.0.6.127\",\"event_handler\":\"\",\"event_handler_enabled\":\"1\",\"execution_time\":\"0\",\"flap_detection_enabled\":\"1\",\"has_been_checked\":\"0\",\"host_id\":\"161\",\"icon_image\":\"\",\"icon_image_alt\":\"\",\"instance_id\":\"1\",\"is_flapping\":\"0\",\"last_check\":\"1970-01-01 05:30:00\",\"last_hard_state\":\"0\",\"last_hard_state_change\":\"1970-01-01 05:30:00\",\"last_notification\":\"1970-01-01 05:30:00\",\"last_state_change\":\"1970-01-01 05:30:00\",\"last_time_down\":\"1970-01-01 05:30:00\",\"last_time_unreachable\":\"1970-01-01 05:30:00\",\"last_time_up\":\"1970-01-01 05:30:00\",\"latency\":\"0\",\"max_check_attempts\":\"10\",\"modified_host_attributes\":\"0\",\"name\":\"10.0.6.127\",\"next_check\":\"2022-03-12 15:49:20\",\"next_notification\":\"1970-01-01 05:30:00\",\"no_more_notifications\":\"0\",\"normal_check_interval\":\"5\",\"notifications_enabled\":\"1\",\"obsess_over_host\":\"1\",\"passive_checks_enabled\":\"1\",\"percent_state_change\":\"0\",\"performance_data\":\"\",\"problem_acknowledged\":\"0\",\"process_performance_data\":\"1\",\"retry_check_interval\":\"1\",\"scheduled_downtime_depth\":\"0\",\"should_be_scheduled\":\"1\",\"state_type\":\"1\",\"status_text\":\"\",\"status_text_long\":\"\",\"status_update_time\":\"2022-03-12 15:44:20\"}",
        "type": "info"
    },
    "host": {
        "ip": "10.0.6.127"
    },
    "input": {
        "type": "httpjson"
    },
    "nagios": {
        "metrics": {
            "host": {
                "address": "10.0.6.127",
                "execution_time": 0,
                "last_check": "1970-01-01T05:30:00.000Z",
                "latency": 0,
                "name": "10.0.6.127",
                "next_check": "2022-03-12T15:49:20.000Z",
                "normal_check_interval": 5,
                "retry_check_interval": 1,
                "status_update_time": "2022-03-12T15:44:20.000Z"
            }
        }
    },
    "related": {
        "ip": [
            "10.0.6.127"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "nagios-host"
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
| nagios.metrics.host.address |  | ip |
| nagios.metrics.host.check_command |  | keyword |
| nagios.metrics.host.execution_time |  | double |
| nagios.metrics.host.last_check |  | date |
| nagios.metrics.host.latency |  | double |
| nagios.metrics.host.name |  | keyword |
| nagios.metrics.host.next_check |  | date |
| nagios.metrics.host.normal_check_interval |  | long |
| nagios.metrics.host.performance_data.pl |  | double |
| nagios.metrics.host.performance_data.rta |  | double |
| nagios.metrics.host.retry_check_interval |  | long |
| nagios.metrics.host.status_text |  | keyword |
| nagios.metrics.host.status_update_time |  | date |
| related.ip | All of the IPs seen on your event. | ip |
| tags | List of keywords used to tag each event. | keyword |


### Service Metrics

This is the `service` dataset.

- This dataset gives services current load, current users, ping, http, ssh, root partition, swap users and total processes metrics.

An example event for `service` looks as following:

```json
{
    "@timestamp": "2022-03-12T15:44:37.000Z",
    "agent": {
        "ephemeral_id": "120bd4d5-0847-4dd8-9793-aaa81476d3c9",
        "id": "01244f10-29f9-4ebb-b2bd-3cea353113de",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "nagios.service",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "01244f10-29f9-4ebb-b2bd-3cea353113de",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-03-14T09:17:18.490Z",
        "dataset": "nagios.http",
        "ingested": "2022-03-14T09:17:19Z",
        "kind": "metrics",
        "module": "nagios",
        "original": "{\"@attributes\":{\"id\":\"60\"},\"acknowledgement_type\":\"0\",\"active_checks_enabled\":\"1\",\"check_command\":\"check_http\",\"check_timeperiod_id\":\"12\",\"check_type\":\"0\",\"current_check_attempt\":\"1\",\"current_notification_number\":\"0\",\"current_state\":\"0\",\"display_name\":\"HTTP\",\"event_handler\":\"\",\"event_handler_enabled\":\"1\",\"execution_time\":\"0.00853\",\"flap_detection_enabled\":\"1\",\"has_been_checked\":\"1\",\"host_address\":\"127.0.0.1\",\"host_alias\":\"localhost\",\"host_display_name\":\"\",\"host_id\":\"11\",\"host_name\":\"localhost\",\"icon_image\":\"\",\"icon_image_alt\":\"\",\"instance_id\":\"1\",\"is_flapping\":\"0\",\"last_check\":\"2022-03-12 15:44:37\",\"last_hard_state\":\"0\",\"last_hard_state_change\":\"2022-03-10 11:56:09\",\"last_notification\":\"1970-01-01 05:30:00\",\"last_state_change\":\"2022-03-10 11:56:09\",\"last_time_critical\":\"1970-01-01 05:30:00\",\"last_time_ok\":\"2022-03-12 15:44:37\",\"last_time_unknown\":\"1970-01-01 05:30:00\",\"last_time_warning\":\"1970-01-01 05:30:00\",\"latency\":\"1.69457\",\"max_check_attempts\":\"4\",\"modified_service_attributes\":\"0\",\"name\":\"HTTP\",\"next_check\":\"2022-03-12 15:49:37\",\"next_notification\":\"1970-01-01 05:30:00\",\"no_more_notifications\":\"0\",\"normal_check_interval\":\"5\",\"notifications_enabled\":\"1\",\"obsess_over_service\":\"1\",\"passive_checks_enabled\":\"1\",\"percent_state_change\":\"0\",\"performance_data\":\"time=0.003326s;;;0.000000 size=3271B;;;0\",\"problem_acknowledged\":\"0\",\"process_performance_data\":\"1\",\"retry_check_interval\":\"1\",\"scheduled_downtime_depth\":\"0\",\"service_id\":\"15\",\"should_be_scheduled\":\"1\",\"state_type\":\"1\",\"status_text\":\"HTTP OK: HTTP/1.1 200 OK - 3271 bytes in 0.003 second response time\",\"status_text_long\":\"\",\"status_update_time\":\"2022-03-12 15:44:37\"}",
        "type": "info"
    },
    "host": {
        "ip": "127.0.0.1"
    },
    "input": {
        "type": "httpjson"
    },
    "nagios": {
        "metrics": {
            "service": {
                "check_command": "check_http",
                "execution_time": 0.00853,
                "host_address": "127.0.0.1",
                "host_name": "localhost",
                "http": {
                    "performance_data": "time=0.003326s;;;0.000000 size=3271B;;;0",
                    "size": 3271,
                    "time": 0.003326
                },
                "last_check": "2022-03-12T15:44:37.000Z",
                "latency": 1.69457,
                "name": "HTTP",
                "next_check": "2022-03-12T15:49:37.000Z",
                "normal_check_interval": 5,
                "retry_check_interval": 1,
                "status_text": "HTTP OK: HTTP/1.1 200 OK - 3271 bytes in 0.003 second response time",
                "status_update_time": "2022-03-12T15:44:37.000Z"
            }
        }
    },
    "related": {
        "ip": [
            "127.0.0.1"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "nagios-service"
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
| nagios.metrics.service.check_command |  | keyword |
| nagios.metrics.service.current_load.load1 |  | double |
| nagios.metrics.service.current_load.load15 |  | double |
| nagios.metrics.service.current_load.load5 |  | double |
| nagios.metrics.service.current_load.performance_data |  | keyword |
| nagios.metrics.service.current_users.performance_data |  | keyword |
| nagios.metrics.service.current_users.users |  | double |
| nagios.metrics.service.custom.performance_data |  | keyword |
| nagios.metrics.service.execution_time |  | double |
| nagios.metrics.service.host_address |  | ip |
| nagios.metrics.service.host_name |  | keyword |
| nagios.metrics.service.http.performance_data |  | keyword |
| nagios.metrics.service.http.size |  | double |
| nagios.metrics.service.http.time |  | double |
| nagios.metrics.service.last_check |  | date |
| nagios.metrics.service.latency |  | double |
| nagios.metrics.service.name |  | keyword |
| nagios.metrics.service.next_check |  | date |
| nagios.metrics.service.normal_check_interval |  | long |
| nagios.metrics.service.performance_data |  | keyword |
| nagios.metrics.service.ping.performance_data |  | keyword |
| nagios.metrics.service.ping.pl |  | double |
| nagios.metrics.service.ping.rta |  | double |
| nagios.metrics.service.process.performance_data |  | keyword |
| nagios.metrics.service.process.total |  | double |
| nagios.metrics.service.retry_check_interval |  | long |
| nagios.metrics.service.root_partition.free_space |  | double |
| nagios.metrics.service.root_partition.performance_data |  | keyword |
| nagios.metrics.service.root_partition.total_space |  | double |
| nagios.metrics.service.root_partition.used_space |  | double |
| nagios.metrics.service.ssh.performance_data |  | keyword |
| nagios.metrics.service.ssh.time |  | double |
| nagios.metrics.service.status_text |  | keyword |
| nagios.metrics.service.status_update_time |  | date |
| nagios.metrics.service.swap_usage.free_swap |  | double |
| nagios.metrics.service.swap_usage.performance_data |  | keyword |
| nagios.metrics.service.swap_usage.total_swap |  | double |
| nagios.metrics.service.swap_usage.used_swap |  | double |
| related.ip | All of the IPs seen on your event. | ip |
| tags | List of keywords used to tag each event. | keyword |

