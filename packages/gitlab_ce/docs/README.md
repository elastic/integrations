# gitlab_ce Integration

This integration is for ingesting logs from [Gitlab Community Edition](https://gitlab.com/rluna-gitlab/gitlab-ce).

- `production`: Collect logs for Rails controller requests received from GitLab.

See [Link to docs](https://docs.gitlab.com/ee/administration/logs/) for more information.

## Compatibility

The Gitlab Community Edition module is currently tested on Linux and Mac with the community edition, version 16.8.5-ce.0.

## Logs

### production

Collect logs for Rails controller requests received from GitLab. Check out the [Gitlab production log docs](https://docs.gitlab.com/ee/administration/logs/#production_jsonlog) for more information.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| container.labels | Image labels. | object |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| gitlab_ce.production.controller |  | keyword |
| gitlab_ce.production.cpu_s |  | long |
| gitlab_ce.production.db_cached_count |  | long |
| gitlab_ce.production.db_ci_cached_count |  | long |
| gitlab_ce.production.db_ci_count |  | long |
| gitlab_ce.production.db_ci_duration_s |  | long |
| gitlab_ce.production.db_ci_replica_cached_count |  | long |
| gitlab_ce.production.db_ci_replica_count |  | long |
| gitlab_ce.production.db_ci_replica_duration_s |  | long |
| gitlab_ce.production.db_ci_replica_txn_count |  | long |
| gitlab_ce.production.db_ci_replica_txn_duration_s |  | long |
| gitlab_ce.production.db_ci_replica_wal_cached_count |  | long |
| gitlab_ce.production.db_ci_replica_wal_count |  | long |
| gitlab_ce.production.db_ci_txn_count |  | long |
| gitlab_ce.production.db_ci_txn_duration_s |  | long |
| gitlab_ce.production.db_ci_wal_cached_count |  | long |
| gitlab_ce.production.db_ci_wal_count |  | long |
| gitlab_ce.production.db_count |  | long |
| gitlab_ce.production.db_duration_s |  | long |
| gitlab_ce.production.db_main_cached_count |  | long |
| gitlab_ce.production.db_main_count |  | long |
| gitlab_ce.production.db_main_duration_s |  | long |
| gitlab_ce.production.db_main_replica_cached_count |  | long |
| gitlab_ce.production.db_main_replica_count |  | long |
| gitlab_ce.production.db_main_replica_duration_s |  | long |
| gitlab_ce.production.db_main_replica_txn_count |  | long |
| gitlab_ce.production.db_main_replica_txn_duration_s |  | long |
| gitlab_ce.production.db_main_replica_wal_cached_count |  | long |
| gitlab_ce.production.db_main_replica_wal_count |  | long |
| gitlab_ce.production.db_main_txn_count |  | long |
| gitlab_ce.production.db_main_txn_duration_s |  | long |
| gitlab_ce.production.db_main_wal_cached_count |  | long |
| gitlab_ce.production.db_main_wal_count |  | long |
| gitlab_ce.production.db_primary_cached_count |  | long |
| gitlab_ce.production.db_primary_count |  | long |
| gitlab_ce.production.db_primary_duration_s |  | long |
| gitlab_ce.production.db_primary_txn_count |  | long |
| gitlab_ce.production.db_primary_txn_duration_s |  | long |
| gitlab_ce.production.db_primary_wal_cached_count |  | long |
| gitlab_ce.production.db_primary_wal_count |  | long |
| gitlab_ce.production.db_replica_cached_count |  | long |
| gitlab_ce.production.db_replica_count |  | long |
| gitlab_ce.production.db_replica_duration_s |  | long |
| gitlab_ce.production.db_replica_txn_count |  | long |
| gitlab_ce.production.db_replica_txn_duration_s |  | long |
| gitlab_ce.production.db_replica_wal_cached_count |  | long |
| gitlab_ce.production.db_replica_wal_count |  | long |
| gitlab_ce.production.db_txn_count |  | long |
| gitlab_ce.production.db_write_count |  | long |
| gitlab_ce.production.format |  | keyword |
| gitlab_ce.production.graphql.complexity |  | long |
| gitlab_ce.production.graphql.depth |  | long |
| gitlab_ce.production.graphql.operation_name |  | keyword |
| gitlab_ce.production.location |  | keyword |
| gitlab_ce.production.mem_bytes |  | long |
| gitlab_ce.production.mem_mallocs |  | long |
| gitlab_ce.production.mem_objects |  | long |
| gitlab_ce.production.mem_total_bytes |  | long |
| gitlab_ce.production.meta.caller_id |  | keyword |
| gitlab_ce.production.meta.client_id |  | keyword |
| gitlab_ce.production.meta.feature_category |  | keyword |
| gitlab_ce.production.meta.remote_ip |  | keyword |
| gitlab_ce.production.meta.search.page |  | keyword |
| gitlab_ce.production.meta.user |  | keyword |
| gitlab_ce.production.meta.user_id |  | long |
| gitlab_ce.production.params.key |  | keyword |
| gitlab_ce.production.params.param_value |  | keyword |
| gitlab_ce.production.params.value |  | keyword |
| gitlab_ce.production.params.value_json.operationName |  | keyword |
| gitlab_ce.production.params.value_json.query |  | keyword |
| gitlab_ce.production.params.value_json.variables |  | keyword |
| gitlab_ce.production.queue_duration_s |  | long |
| gitlab_ce.production.redis_allowed_cross_slot_calls |  | long |
| gitlab_ce.production.redis_cache_calls |  | long |
| gitlab_ce.production.redis_cache_duration_s |  | long |
| gitlab_ce.production.redis_cache_read_bytes |  | long |
| gitlab_ce.production.redis_cache_write_bytes |  | long |
| gitlab_ce.production.redis_calls |  | long |
| gitlab_ce.production.redis_db_load_balancing_calls |  | long |
| gitlab_ce.production.redis_db_load_balancing_duration_s |  | long |
| gitlab_ce.production.redis_db_load_balancing_write_bytes |  | long |
| gitlab_ce.production.redis_duration_s |  | long |
| gitlab_ce.production.redis_feature_flag_calls |  | long |
| gitlab_ce.production.redis_feature_flag_duration_s |  | long |
| gitlab_ce.production.redis_feature_flag_read_bytes |  | long |
| gitlab_ce.production.redis_feature_flag_write_bytes |  | long |
| gitlab_ce.production.redis_read_bytes |  | long |
| gitlab_ce.production.redis_sessions_allowed_cross_slot_calls |  | long |
| gitlab_ce.production.redis_sessions_calls |  | long |
| gitlab_ce.production.redis_sessions_duration_s |  | long |
| gitlab_ce.production.redis_sessions_read_bytes |  | long |
| gitlab_ce.production.redis_sessions_write_bytes |  | long |
| gitlab_ce.production.redis_write_bytes |  | long |
| gitlab_ce.production.remote_ip |  | keyword |
| gitlab_ce.production.request_urgency |  | keyword |
| gitlab_ce.production.target_duration_s |  | long |
| gitlab_ce.production.time |  | keyword |
| gitlab_ce.production.view_duration_s |  | long |
| gitlab_ce.production.worker_id |  | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.idxhi | The high-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.idxlo | The low-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.file.vol | The serial number of the volume that contains a file. (Windows-only) | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |


An example event for `production` looks as following:

```json
{
    "@timestamp": "2024-04-03T20:44:09.068Z",
    "agent": {
        "ephemeral_id": "cc904b63-5daa-4c56-b8fc-ef7813bea8fd",
        "id": "95056c50-6076-4e1c-833d-03bbacd506e4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.2"
    },
    "data_stream": {
        "dataset": "gitlab_ce.production",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "95056c50-6076-4e1c-833d-03bbacd506e4",
        "snapshot": false,
        "version": "8.13.2"
    },
    "event": {
        "action": "index",
        "agent_id_status": "verified",
        "dataset": "gitlab_ce.production",
        "duration": 24200000,
        "id": "0bb7a10d-8da7-4499-8759-99ebe323f4b1",
        "ingested": "2024-04-29T16:21:11Z",
        "original": "{\"method\":\"GET\",\"path\":\"/\",\"format\":\"html\",\"controller\":\"RootController\",\"action\":\"index\",\"status\":302,\"location\":\"http://example.org/users/sign_in\",\"time\":\"2024-04-03T20:44:09.068Z\",\"params\":[],\"correlation_id\":\"0bb7a10d-8da7-4499-8759-99ebe323f4b1\",\"meta.caller_id\":\"RootController#index\",\"meta.feature_category\":\"groups_and_projects\",\"meta.client_id\":\"ip/\",\"request_urgency\":\"low\",\"target_duration_s\":5,\"redis_calls\":26,\"redis_duration_s\":0.005135,\"redis_read_bytes\":26,\"redis_write_bytes\":4284,\"redis_feature_flag_calls\":26,\"redis_feature_flag_duration_s\":0.005135,\"redis_feature_flag_read_bytes\":26,\"redis_feature_flag_write_bytes\":4284,\"db_count\":13,\"db_write_count\":0,\"db_cached_count\":0,\"db_txn_count\":0,\"db_replica_txn_count\":0,\"db_primary_txn_count\":0,\"db_main_txn_count\":0,\"db_ci_txn_count\":0,\"db_main_replica_txn_count\":0,\"db_ci_replica_txn_count\":0,\"db_replica_count\":0,\"db_primary_count\":13,\"db_main_count\":13,\"db_ci_count\":0,\"db_main_replica_count\":0,\"db_ci_replica_count\":0,\"db_replica_cached_count\":0,\"db_primary_cached_count\":0,\"db_main_cached_count\":0,\"db_ci_cached_count\":0,\"db_main_replica_cached_count\":0,\"db_ci_replica_cached_count\":0,\"db_replica_wal_count\":0,\"db_primary_wal_count\":0,\"db_main_wal_count\":0,\"db_ci_wal_count\":0,\"db_main_replica_wal_count\":0,\"db_ci_replica_wal_count\":0,\"db_replica_wal_cached_count\":0,\"db_primary_wal_cached_count\":0,\"db_main_wal_cached_count\":0,\"db_ci_wal_cached_count\":0,\"db_main_replica_wal_cached_count\":0,\"db_ci_replica_wal_cached_count\":0,\"db_replica_txn_duration_s\":0.0,\"db_primary_txn_duration_s\":0.0,\"db_main_txn_duration_s\":0.0,\"db_ci_txn_duration_s\":0.0,\"db_main_replica_txn_duration_s\":0.0,\"db_ci_replica_txn_duration_s\":0.0,\"db_replica_duration_s\":0.0,\"db_primary_duration_s\":0.01,\"db_main_duration_s\":0.01,\"db_ci_duration_s\":0.0,\"db_main_replica_duration_s\":0.0,\"db_ci_replica_duration_s\":0.0,\"cpu_s\":0.047579,\"mem_objects\":32870,\"mem_bytes\":2376584,\"mem_mallocs\":11255,\"mem_total_bytes\":3691384,\"pid\":857,\"worker_id\":\"puma_master\",\"rate_limiting_gates\":[],\"db_duration_s\":0.00158,\"view_duration_s\":0.0,\"duration_s\":0.0242}",
        "type": [
            "info"
        ]
    },
    "gitlab_ce": {
        "production": {
            "controller": "RootController",
            "cpu_s": 0.047579,
            "db_cached_count": 0,
            "db_ci_cached_count": 0,
            "db_ci_count": 0,
            "db_ci_duration_s": 0,
            "db_ci_replica_cached_count": 0,
            "db_ci_replica_count": 0,
            "db_ci_replica_duration_s": 0,
            "db_ci_replica_txn_count": 0,
            "db_ci_replica_txn_duration_s": 0,
            "db_ci_replica_wal_cached_count": 0,
            "db_ci_replica_wal_count": 0,
            "db_ci_txn_count": 0,
            "db_ci_txn_duration_s": 0,
            "db_ci_wal_cached_count": 0,
            "db_ci_wal_count": 0,
            "db_count": 13,
            "db_duration_s": 0.00158,
            "db_main_cached_count": 0,
            "db_main_count": 13,
            "db_main_duration_s": 0.01,
            "db_main_replica_cached_count": 0,
            "db_main_replica_count": 0,
            "db_main_replica_duration_s": 0,
            "db_main_replica_txn_count": 0,
            "db_main_replica_txn_duration_s": 0,
            "db_main_replica_wal_cached_count": 0,
            "db_main_replica_wal_count": 0,
            "db_main_txn_count": 0,
            "db_main_txn_duration_s": 0,
            "db_main_wal_cached_count": 0,
            "db_main_wal_count": 0,
            "db_primary_cached_count": 0,
            "db_primary_count": 13,
            "db_primary_duration_s": 0.01,
            "db_primary_txn_count": 0,
            "db_primary_txn_duration_s": 0,
            "db_primary_wal_cached_count": 0,
            "db_primary_wal_count": 0,
            "db_replica_cached_count": 0,
            "db_replica_count": 0,
            "db_replica_duration_s": 0,
            "db_replica_txn_count": 0,
            "db_replica_txn_duration_s": 0,
            "db_replica_wal_cached_count": 0,
            "db_replica_wal_count": 0,
            "db_txn_count": 0,
            "db_write_count": 0,
            "format": "html",
            "location": "http://example.org/users/sign_in",
            "mem_bytes": 2376584,
            "mem_mallocs": 11255,
            "mem_objects": 32870,
            "mem_total_bytes": 3691384,
            "meta.caller_id": "RootController#index",
            "meta.client_id": "ip/",
            "meta.feature_category": "groups_and_projects",
            "redis_calls": 26,
            "redis_duration_s": 0.005135,
            "redis_feature_flag_calls": 26,
            "redis_feature_flag_duration_s": 0.005135,
            "redis_feature_flag_read_bytes": 26,
            "redis_feature_flag_write_bytes": 4284,
            "redis_read_bytes": 26,
            "redis_write_bytes": 4284,
            "request_urgency": "low",
            "target_duration_s": 5,
            "time": "2024-04-03T20:44:09.068Z",
            "view_duration_s": 0
        }
    },
    "http": {
        "request": {
            "method": "GET"
        },
        "response": {
            "status_code": 302
        }
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "device_id": "113",
            "inode": "119411692",
            "path": "/tmp/service_logs/test-gitlab-ce-production.log"
        },
        "offset": 9771
    },
    "process": {
        "name": "puma_master",
        "pid": 857
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "gitlab_ce-production"
    ],
    "url": {
        "path": "/"
    }
}
```