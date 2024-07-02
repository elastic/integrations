# VMware Carbon Black EDR Integration

The VMware Carbon Black EDR integration collects EDR Server and raw Endpoint events exported by [Carbon Black EDR Event Forwarder.](https://github.com/carbonblack/cb-event-forwarder) The following output methods are supported: `http`, `tcp`, `udp` and `file`.

## Compatibility

This integration has been tested with the 3.7.4 version of EDR Event Forwarder.

## Configuration

The following configuration is necessary in `cb-event-forwarder.conf`:

- `output_format=json` (default)

For `http` output:
  - `output_type=http`
  - `http_post_template=[{{range .Events}}{{.EventText}}{{end}}]`
  - `content_type=application/json` (default)

For `tcp` output:
  - `output_type=tcp`
  - `tcpout=<Address of Elastic Agent>:<port>`

For `udp` output:
- `output_type=tcp`
- `tcpout=<Address of Elastic Agent>:<port>`

For `file` output:
- `output_type=file`
- `outfile=<path to a file readable by Elastic Agent>`

An example event for `log` looks as following:

```json
{
    "@timestamp": "2014-04-11T19:21:33.682Z",
    "agent": {
        "ephemeral_id": "7bb86a18-d262-4348-b206-131e38d2d1c8",
        "id": "9cb9fa70-f3e9-45d8-b1cb-61425bd93e1a",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0-beta1"
    },
    "carbonblack": {
        "edr": {
            "event_timestamp": 1397244093.682,
            "feed_id": 7,
            "feed_name": "dxmtest1",
            "ioc_attr": {},
            "md5": "506708142BC63DABA64F2D3AD1DCD5BF",
            "report_id": "dxmtest1_04",
            "sensor_id": 3321
        }
    },
    "data_stream": {
        "dataset": "carbonblack_edr.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9cb9fa70-f3e9-45d8-b1cb-61425bd93e1a",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "action": "unknown",
        "agent_id_status": "verified",
        "dataset": "carbonblack_edr.log",
        "ingested": "2022-01-25T07:45:03Z",
        "kind": "event",
        "original": "{\"md5\":\"506708142BC63DABA64F2D3AD1DCD5BF\",\"report_id\":\"dxmtest1_04\",\"ioc_type\":\"md5\",\"ioc_value\":\"506708142bc63daba64f2d3ad1dcd5bf\",\"ioc_attr\":{},\"feed_id\":7,\"hostname\":\"FS-SEA-529\",\"sensor_id\":3321,\"cb_version\":\"4.2.1.140808.1059\",\"server_name\":\"localhost.localdomain\",\"feed_name\":\"dxmtest1\",\"event_timestamp\":1397244093.682}\n"
    },
    "host": {
        "name": "FS-SEA-529"
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "source": {
            "address": "172.19.0.4:46263"
        }
    },
    "observer": {
        "name": "localhost.localdomain",
        "product": "Carbon Black EDR",
        "type": "edr",
        "vendor": "VMWare",
        "version": "4.2.1.140808.1059"
    },
    "tags": [
        "carbonblack_edr-log",
        "forwarded",
        "preserve_original_event"
    ],
    "threat": {
        "indicator": {
            "file": {
                "hash": {
                    "md5": "506708142bc63daba64f2d3ad1dcd5bf"
                }
            },
            "type": "file"
        }
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| carbonblack.edr.action |  | keyword |
| carbonblack.edr.actiontype |  | keyword |
| carbonblack.edr.alert_severity |  | double |
| carbonblack.edr.alert_type |  | keyword |
| carbonblack.edr.blocked |  | boolean |
| carbonblack.edr.blocked_event |  | keyword |
| carbonblack.edr.blocked_reason |  | keyword |
| carbonblack.edr.blocked_result |  | keyword |
| carbonblack.edr.cb_server |  | keyword |
| carbonblack.edr.cb_version |  | keyword |
| carbonblack.edr.child_command_line |  | keyword |
| carbonblack.edr.child_pid |  | long |
| carbonblack.edr.child_process_guid |  | keyword |
| carbonblack.edr.child_suppressed |  | boolean |
| carbonblack.edr.child_username |  | keyword |
| carbonblack.edr.childproc_count |  | long |
| carbonblack.edr.childproc_type |  | keyword |
| carbonblack.edr.command_line |  | keyword |
| carbonblack.edr.comms_ip |  | keyword |
| carbonblack.edr.compressed_size |  | long |
| carbonblack.edr.computer_name |  | keyword |
| carbonblack.edr.created |  | boolean |
| carbonblack.edr.created_time |  | keyword |
| carbonblack.edr.cross_process_type |  | keyword |
| carbonblack.edr.crossproc_count |  | long |
| carbonblack.edr.digsig.issuer_name |  | keyword |
| carbonblack.edr.digsig.program_name |  | keyword |
| carbonblack.edr.digsig.publisher |  | keyword |
| carbonblack.edr.digsig.result |  | keyword |
| carbonblack.edr.digsig.result_code |  | keyword |
| carbonblack.edr.digsig.sign_time |  | keyword |
| carbonblack.edr.digsig.subject_name |  | keyword |
| carbonblack.edr.direction |  | keyword |
| carbonblack.edr.doc |  | flattened |
| carbonblack.edr.domain |  | keyword |
| carbonblack.edr.emet_timestamp |  | long |
| carbonblack.edr.event_timestamp |  | double |
| carbonblack.edr.event_type |  | keyword |
| carbonblack.edr.expect_followon_w_md5 |  | boolean |
| carbonblack.edr.feed_id |  | keyword |
| carbonblack.edr.feed_name |  | keyword |
| carbonblack.edr.feed_rating |  | double |
| carbonblack.edr.file_md5 |  | keyword |
| carbonblack.edr.file_path |  | keyword |
| carbonblack.edr.file_sha256 |  | keyword |
| carbonblack.edr.filemod_count |  | long |
| carbonblack.edr.filetype |  | keyword |
| carbonblack.edr.filetype_name |  | keyword |
| carbonblack.edr.filtering_known_dlls |  | boolean |
| carbonblack.edr.group |  | keyword |
| carbonblack.edr.host |  | keyword |
| carbonblack.edr.hostname |  | keyword |
| carbonblack.edr.icon |  | keyword |
| carbonblack.edr.image_file_header |  | keyword |
| carbonblack.edr.interface_ip |  | keyword |
| carbonblack.edr.ioc_attr |  | flattened |
| carbonblack.edr.ioc_confidence |  | double |
| carbonblack.edr.ioc_type |  | keyword |
| carbonblack.edr.ioc_value |  | keyword |
| carbonblack.edr.ipv4 |  | keyword |
| carbonblack.edr.is_target |  | boolean |
| carbonblack.edr.ja3 |  | keyword |
| carbonblack.edr.ja3s |  | keyword |
| carbonblack.edr.link_child |  | keyword |
| carbonblack.edr.link_md5 |  | keyword |
| carbonblack.edr.link_parent |  | keyword |
| carbonblack.edr.link_process |  | keyword |
| carbonblack.edr.link_sensor |  | keyword |
| carbonblack.edr.link_target |  | keyword |
| carbonblack.edr.local_ip |  | keyword |
| carbonblack.edr.local_port |  | long |
| carbonblack.edr.log_id |  | keyword |
| carbonblack.edr.log_message |  | keyword |
| carbonblack.edr.md5 |  | keyword |
| carbonblack.edr.mitigation |  | keyword |
| carbonblack.edr.modload_count |  | long |
| carbonblack.edr.netconn_count |  | long |
| carbonblack.edr.os_type |  | keyword |
| carbonblack.edr.parent_create_time |  | long |
| carbonblack.edr.parent_guid |  | keyword |
| carbonblack.edr.parent_md5 |  | keyword |
| carbonblack.edr.parent_path |  | keyword |
| carbonblack.edr.parent_pid |  | long |
| carbonblack.edr.parent_process_guid |  | keyword |
| carbonblack.edr.parent_sha256 |  | keyword |
| carbonblack.edr.path |  | keyword |
| carbonblack.edr.pid |  | long |
| carbonblack.edr.port |  | long |
| carbonblack.edr.process_guid |  | keyword |
| carbonblack.edr.process_id |  | keyword |
| carbonblack.edr.process_name |  | keyword |
| carbonblack.edr.process_path |  | keyword |
| carbonblack.edr.process_unique_id |  | keyword |
| carbonblack.edr.protocol |  | keyword |
| carbonblack.edr.proxy |  | boolean |
| carbonblack.edr.regmod_count |  | long |
| carbonblack.edr.remote_ip |  | keyword |
| carbonblack.edr.remote_port |  | long |
| carbonblack.edr.report_id |  | keyword |
| carbonblack.edr.report_score |  | long |
| carbonblack.edr.requested_access |  | long |
| carbonblack.edr.scores.alliance_score_srstrust |  | long |
| carbonblack.edr.scores.alliance_score_virustotal |  | long |
| carbonblack.edr.script |  | keyword |
| carbonblack.edr.script_sha256 |  | keyword |
| carbonblack.edr.segment_id |  | keyword |
| carbonblack.edr.sensor_criticality |  | double |
| carbonblack.edr.sensor_id |  | keyword |
| carbonblack.edr.server_name |  | keyword |
| carbonblack.edr.sha256 |  | keyword |
| carbonblack.edr.size |  | long |
| carbonblack.edr.status |  | keyword |
| carbonblack.edr.tamper |  | boolean |
| carbonblack.edr.tamper_sent |  | boolean |
| carbonblack.edr.tamper_type |  | keyword |
| carbonblack.edr.target_create_time |  | long |
| carbonblack.edr.target_md5 |  | keyword |
| carbonblack.edr.target_path |  | keyword |
| carbonblack.edr.target_pid |  | long |
| carbonblack.edr.target_process_guid |  | keyword |
| carbonblack.edr.target_sha256 |  | keyword |
| carbonblack.edr.timestamp |  | double |
| carbonblack.edr.type |  | keyword |
| carbonblack.edr.uid |  | keyword |
| carbonblack.edr.unique_id |  | keyword |
| carbonblack.edr.username |  | keyword |
| carbonblack.edr.utf8_comments |  | keyword |
| carbonblack.edr.utf8_company_name |  | keyword |
| carbonblack.edr.utf8_copied_module_length |  | long |
| carbonblack.edr.utf8_file_description |  | keyword |
| carbonblack.edr.utf8_file_version |  | keyword |
| carbonblack.edr.utf8_internal_name |  | keyword |
| carbonblack.edr.utf8_legal_copyright |  | keyword |
| carbonblack.edr.utf8_legal_trademark |  | keyword |
| carbonblack.edr.utf8_on_disk_filename |  | keyword |
| carbonblack.edr.utf8_original_file_name |  | keyword |
| carbonblack.edr.utf8_private_build |  | keyword |
| carbonblack.edr.utf8_product_description |  | keyword |
| carbonblack.edr.utf8_product_name |  | keyword |
| carbonblack.edr.utf8_product_version |  | keyword |
| carbonblack.edr.utf8_special_build |  | keyword |
| carbonblack.edr.watchlist_id |  | keyword |
| carbonblack.edr.watchlist_name |  | keyword |
| carbonblack.edr.watchlists.watchlist_1 |  | keyword |
| carbonblack.edr.watchlists.watchlist_7 |  | keyword |
| carbonblack.edr.watchlists.watchlist_9 |  | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


