# gitlab_ce Integration

This integration is for ingesting logs from [Gitlab Community Edition](https://gitlab.com/rluna-gitlab/gitlab-ce).

- `api`: Collect logs for HTTP requests made to the Gitlab API

- `production`: Collect logs for Rails controller requests received from GitLab.

See [Link to docs](https://docs.gitlab.com/ee/administration/logs/) for more information.

## Compatibility

The Gitlab Community Edition module is currently tested on Linux and Mac with the community edition, version 16.8.5-ce.0.

## Logs

### api

Collect logs for HTTP requests made to the Gitlab API. Check out the [Gitlab api log docs](https://docs.gitlab.com/ee/administration/logs/#api_jsonlog) for more information.

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
| gitlab_ce.api.correlation_id |  | keyword |
| gitlab_ce.api.cpu_s |  | long |
| gitlab_ce.api.db_cached_count |  | long |
| gitlab_ce.api.db_ci_cached_count |  | long |
| gitlab_ce.api.db_ci_count |  | long |
| gitlab_ce.api.db_ci_duration_s |  | long |
| gitlab_ce.api.db_ci_replica_cached_count |  | long |
| gitlab_ce.api.db_ci_replica_count |  | long |
| gitlab_ce.api.db_ci_replica_duration_s |  | long |
| gitlab_ce.api.db_ci_replica_txn_count |  | long |
| gitlab_ce.api.db_ci_replica_txn_duration_s |  | long |
| gitlab_ce.api.db_ci_replica_wal_cached_count |  | long |
| gitlab_ce.api.db_ci_replica_wal_count |  | long |
| gitlab_ce.api.db_ci_txn_count |  | long |
| gitlab_ce.api.db_ci_txn_duration_s |  | long |
| gitlab_ce.api.db_ci_wal_cached_count |  | long |
| gitlab_ce.api.db_ci_wal_count |  | long |
| gitlab_ce.api.db_count |  | long |
| gitlab_ce.api.db_duration_s |  | long |
| gitlab_ce.api.db_main_cached_count |  | long |
| gitlab_ce.api.db_main_count |  | long |
| gitlab_ce.api.db_main_duration_s |  | long |
| gitlab_ce.api.db_main_replica_cached_count |  | long |
| gitlab_ce.api.db_main_replica_count |  | long |
| gitlab_ce.api.db_main_replica_duration_s |  | long |
| gitlab_ce.api.db_main_replica_txn_count |  | long |
| gitlab_ce.api.db_main_replica_txn_duration_s |  | long |
| gitlab_ce.api.db_main_replica_wal_cached_count |  | long |
| gitlab_ce.api.db_main_replica_wal_count |  | long |
| gitlab_ce.api.db_main_txn_count |  | long |
| gitlab_ce.api.db_main_txn_duration_s |  | long |
| gitlab_ce.api.db_main_wal_cached_count |  | long |
| gitlab_ce.api.db_main_wal_count |  | long |
| gitlab_ce.api.db_primary_cached_count |  | long |
| gitlab_ce.api.db_primary_count |  | long |
| gitlab_ce.api.db_primary_duration_s |  | long |
| gitlab_ce.api.db_primary_txn_count |  | long |
| gitlab_ce.api.db_primary_txn_duration_s |  | long |
| gitlab_ce.api.db_primary_wal_cached_count |  | long |
| gitlab_ce.api.db_primary_wal_count |  | long |
| gitlab_ce.api.db_replica_cached_count |  | long |
| gitlab_ce.api.db_replica_count |  | long |
| gitlab_ce.api.db_replica_duration_s |  | long |
| gitlab_ce.api.db_replica_txn_count |  | long |
| gitlab_ce.api.db_replica_txn_duration_s |  | long |
| gitlab_ce.api.db_replica_wal_cached_count |  | long |
| gitlab_ce.api.db_replica_wal_count |  | long |
| gitlab_ce.api.db_txn_count |  | long |
| gitlab_ce.api.db_write_count |  | long |
| gitlab_ce.api.duration_s |  | long |
| gitlab_ce.api.mem_bytes |  | long |
| gitlab_ce.api.mem_mallocs |  | long |
| gitlab_ce.api.mem_objects |  | long |
| gitlab_ce.api.mem_total_bytes |  | long |
| gitlab_ce.api.meta.caller_id |  | keyword |
| gitlab_ce.api.meta.client_id |  | keyword |
| gitlab_ce.api.meta.feature_category |  | keyword |
| gitlab_ce.api.meta.remote_ip |  | keyword |
| gitlab_ce.api.meta.user |  | keyword |
| gitlab_ce.api.meta.user_id |  | long |
| gitlab_ce.api.params.key |  | keyword |
| gitlab_ce.api.params.value |  | keyword |
| gitlab_ce.api.queue_duration_s |  | long |
| gitlab_ce.api.redis_allowed_cross_slot_calls |  | long |
| gitlab_ce.api.redis_cache_calls |  | long |
| gitlab_ce.api.redis_cache_duration_s |  | long |
| gitlab_ce.api.redis_cache_read_bytes |  | long |
| gitlab_ce.api.redis_cache_write_bytes |  | long |
| gitlab_ce.api.redis_calls |  | long |
| gitlab_ce.api.redis_db_load_balancing_calls |  | long |
| gitlab_ce.api.redis_db_load_balancing_duration_s |  | long |
| gitlab_ce.api.redis_db_load_balancing_write_bytes |  | long |
| gitlab_ce.api.redis_duration_s |  | long |
| gitlab_ce.api.redis_feature_flag_calls |  | long |
| gitlab_ce.api.redis_feature_flag_duration_s |  | long |
| gitlab_ce.api.redis_feature_flag_read_bytes |  | long |
| gitlab_ce.api.redis_feature_flag_write_bytes |  | long |
| gitlab_ce.api.redis_read_bytes |  | long |
| gitlab_ce.api.redis_sessions_allowed_cross_slot_calls |  | long |
| gitlab_ce.api.redis_sessions_calls |  | long |
| gitlab_ce.api.redis_sessions_duration_s |  | long |
| gitlab_ce.api.redis_sessions_read_bytes |  | long |
| gitlab_ce.api.redis_sessions_write_bytes |  | long |
| gitlab_ce.api.redis_write_bytes |  | long |
| gitlab_ce.api.request_urgency |  | keyword |
| gitlab_ce.api.route |  | keyword |
| gitlab_ce.api.target_duration_s |  | long |
| gitlab_ce.api.time |  | keyword |
| gitlab_ce.api.token_id |  | long |
| gitlab_ce.api.token_type |  | keyword |
| gitlab_ce.api.view_duration_s |  | long |
| gitlab_ce.api.worker_id |  | keyword |
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


An example event for `api` looks as following:

```json
{
    "@timestamp": "2024-04-29T17:06:12.231Z",
    "agent": {
        "ephemeral_id": "038ebfed-69a2-4ab2-953c-66330e1c429e",
        "id": "95056c50-6076-4e1c-833d-03bbacd506e4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.2"
    },
    "data_stream": {
        "dataset": "gitlab_ce.api",
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
        "agent_id_status": "verified",
        "category": [
            "api"
        ],
        "dataset": "gitlab_ce.api",
        "duration": 19690,
        "ingested": "2024-04-30T19:11:30Z",
        "original": "{\"time\":\"2024-04-29T17:06:12.231Z\",\"severity\":\"INFO\",\"duration_s\":0.01969,\"db_duration_s\":0.0,\"view_duration_s\":0.01969,\"status\":200,\"method\":\"GET\",\"path\":\"/api/v4/geo/proxy\",\"params\":[],\"host\":\"localhost\",\"remote_ip\":\"127.0.0.1\",\"ua\":\"Go-http-client/1.1\",\"route\":\"/api/:version/geo/proxy\",\"db_count\":0,\"db_write_count\":0,\"db_cached_count\":0,\"db_txn_count\":0,\"db_replica_txn_count\":0,\"db_primary_txn_count\":0,\"db_main_txn_count\":0,\"db_ci_txn_count\":0,\"db_main_replica_txn_count\":0,\"db_ci_replica_txn_count\":0,\"db_replica_count\":0,\"db_primary_count\":0,\"db_main_count\":0,\"db_ci_count\":0,\"db_main_replica_count\":0,\"db_ci_replica_count\":0,\"db_replica_cached_count\":0,\"db_primary_cached_count\":0,\"db_main_cached_count\":0,\"db_ci_cached_count\":0,\"db_main_replica_cached_count\":0,\"db_ci_replica_cached_count\":0,\"db_replica_wal_count\":0,\"db_primary_wal_count\":0,\"db_main_wal_count\":0,\"db_ci_wal_count\":0,\"db_main_replica_wal_count\":0,\"db_ci_replica_wal_count\":0,\"db_replica_wal_cached_count\":0,\"db_primary_wal_cached_count\":0,\"db_main_wal_cached_count\":0,\"db_ci_wal_cached_count\":0,\"db_main_replica_wal_cached_count\":0,\"db_ci_replica_wal_cached_count\":0,\"db_replica_txn_duration_s\":0.0,\"db_primary_txn_duration_s\":0.0,\"db_main_txn_duration_s\":0.0,\"db_ci_txn_duration_s\":0.0,\"db_main_replica_txn_duration_s\":0.0,\"db_ci_replica_txn_duration_s\":0.0,\"db_replica_duration_s\":0.0,\"db_primary_duration_s\":0.0,\"db_main_duration_s\":0.0,\"db_ci_duration_s\":0.0,\"db_main_replica_duration_s\":0.0,\"db_ci_replica_duration_s\":0.0,\"cpu_s\":0.063617,\"mem_objects\":13367,\"mem_bytes\":1633512,\"mem_mallocs\":7711,\"mem_total_bytes\":2168192,\"pid\":1067,\"worker_id\":\"puma_4\",\"rate_limiting_gates\":[],\"correlation_id\":\"7ff5f562-f16f-4a93-b2ac-f771c81b0495\",\"meta.caller_id\":\"GET /api/:version/geo/proxy\",\"meta.remote_ip\":\"127.0.0.1\",\"meta.feature_category\":\"geo_replication\",\"meta.client_id\":\"ip/127.0.0.1\",\"request_urgency\":\"low\",\"target_duration_s\":5}",
        "provider": "GET /api/:version/geo/proxy",
        "type": [
            "info"
        ]
    },
    "gitlab_ce": {
        "api": {
            "correlation_id": "7ff5f562-f16f-4a93-b2ac-f771c81b0495",
            "cpu_s": 0.063617,
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
            "db_count": 0,
            "db_duration_s": 0,
            "db_main_cached_count": 0,
            "db_main_count": 0,
            "db_main_duration_s": 0,
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
            "db_primary_count": 0,
            "db_primary_duration_s": 0,
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
            "duration_s": 0.01969,
            "mem_bytes": 1633512,
            "mem_mallocs": 7711,
            "mem_objects": 13367,
            "mem_total_bytes": 2168192,
            "meta": {
                "client_id": "ip/127.0.0.1",
                "feature_category": "geo_replication",
                "remote_ip": "127.0.0.1"
            },
            "request_urgency": "low",
            "route": "/api/:version/geo/proxy",
            "target_duration_s": 5,
            "time": "2024-04-29T17:06:12.231Z",
            "view_duration_s": 0.01969,
            "worker_id": "puma_4"
        }
    },
    "http": {
        "request": {
            "method": "GET"
        },
        "response": {
            "status_code": 200
        }
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "device_id": "113",
            "inode": "119521572",
            "path": "/tmp/service_logs/test-gitlab-ce-api.log"
        },
        "level": "INFO",
        "offset": 0
    },
    "process": {
        "pid": 1067
    },
    "source": {
        "ip": [
            "127.0.0.1"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "gitlab_ce-api"
    ],
    "url": {
        "domain": "localhost",
        "path": "/api/v4/geo/proxy"
    },
    "user_agent": {
        "original": "Go-http-client/1.1"
    }
}
```

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
| gitlab_ce.production.graphql.used_deprecated_fields |  | keyword |
| gitlab_ce.production.graphql.used_fields |  | keyword |
| gitlab_ce.production.graphql.variables |  | keyword |
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
| gitlab_ce.production.params.value |  | keyword |
| gitlab_ce.production.params.value_json.email |  | keyword |
| gitlab_ce.production.params.value_json.first_name |  | keyword |
| gitlab_ce.production.params.value_json.last_name |  | keyword |
| gitlab_ce.production.params.value_json.login |  | keyword |
| gitlab_ce.production.params.value_json.operationName |  | keyword |
| gitlab_ce.production.params.value_json.password |  | keyword |
| gitlab_ce.production.params.value_json.query |  | keyword |
| gitlab_ce.production.params.value_json.remember_me |  | keyword |
| gitlab_ce.production.params.value_json.username |  | keyword |
| gitlab_ce.production.params.value_json.variables |  | keyword |
| gitlab_ce.production.queue_duration_s |  | long |
| gitlab_ce.production.rate_limiting_gates |  | keyword |
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
| gitlab_ce.production.redis_queues_calls |  | long |
| gitlab_ce.production.redis_queues_duration_s |  | long |
| gitlab_ce.production.redis_queues_metadata_calls |  | long |
| gitlab_ce.production.redis_queues_metadata_duration_s |  | long |
| gitlab_ce.production.redis_queues_metadata_read_bytes |  | long |
| gitlab_ce.production.redis_queues_metadata_write_bytes |  | long |
| gitlab_ce.production.redis_queues_read_bytes |  | long |
| gitlab_ce.production.redis_queues_write_bytes |  | long |
| gitlab_ce.production.redis_rate_limiting_calls |  | long |
| gitlab_ce.production.redis_rate_limiting_duration_s |  | long |
| gitlab_ce.production.redis_rate_limiting_read_bytes |  | long |
| gitlab_ce.production.redis_rate_limiting_write_bytes |  | long |
| gitlab_ce.production.redis_read_bytes |  | long |
| gitlab_ce.production.redis_sessions_allowed_cross_slot_calls |  | long |
| gitlab_ce.production.redis_sessions_calls |  | long |
| gitlab_ce.production.redis_sessions_duration_s |  | long |
| gitlab_ce.production.redis_sessions_read_bytes |  | long |
| gitlab_ce.production.redis_sessions_write_bytes |  | long |
| gitlab_ce.production.redis_shared_state_calls |  | long |
| gitlab_ce.production.redis_shared_state_duration_s |  | long |
| gitlab_ce.production.redis_shared_state_read_bytes |  | long |
| gitlab_ce.production.redis_shared_state_write_bytes |  | long |
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
        "ephemeral_id": "2ace8861-75e1-40f8-b074-03eb7b961811",
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
        "ingested": "2024-04-30T19:12:22Z",
        "original": "{\"method\":\"GET\",\"path\":\"/\",\"format\":\"html\",\"controller\":\"RootController\",\"action\":\"index\",\"status\":302,\"location\":\"http://example.org/users/sign_in\",\"time\":\"2024-04-03T20:44:09.068Z\",\"params\":[],\"correlation_id\":\"0bb7a10d-8da7-4499-8759-99ebe323f4b1\",\"meta.caller_id\":\"RootController#index\",\"meta.feature_category\":\"groups_and_projects\",\"meta.client_id\":\"ip/\",\"request_urgency\":\"low\",\"target_duration_s\":5,\"redis_calls\":26,\"redis_duration_s\":0.005135,\"redis_read_bytes\":26,\"redis_write_bytes\":4284,\"redis_feature_flag_calls\":26,\"redis_feature_flag_duration_s\":0.005135,\"redis_feature_flag_read_bytes\":26,\"redis_feature_flag_write_bytes\":4284,\"db_count\":13,\"db_write_count\":0,\"db_cached_count\":0,\"db_txn_count\":0,\"db_replica_txn_count\":0,\"db_primary_txn_count\":0,\"db_main_txn_count\":0,\"db_ci_txn_count\":0,\"db_main_replica_txn_count\":0,\"db_ci_replica_txn_count\":0,\"db_replica_count\":0,\"db_primary_count\":13,\"db_main_count\":13,\"db_ci_count\":0,\"db_main_replica_count\":0,\"db_ci_replica_count\":0,\"db_replica_cached_count\":0,\"db_primary_cached_count\":0,\"db_main_cached_count\":0,\"db_ci_cached_count\":0,\"db_main_replica_cached_count\":0,\"db_ci_replica_cached_count\":0,\"db_replica_wal_count\":0,\"db_primary_wal_count\":0,\"db_main_wal_count\":0,\"db_ci_wal_count\":0,\"db_main_replica_wal_count\":0,\"db_ci_replica_wal_count\":0,\"db_replica_wal_cached_count\":0,\"db_primary_wal_cached_count\":0,\"db_main_wal_cached_count\":0,\"db_ci_wal_cached_count\":0,\"db_main_replica_wal_cached_count\":0,\"db_ci_replica_wal_cached_count\":0,\"db_replica_txn_duration_s\":0.0,\"db_primary_txn_duration_s\":0.0,\"db_main_txn_duration_s\":0.0,\"db_ci_txn_duration_s\":0.0,\"db_main_replica_txn_duration_s\":0.0,\"db_ci_replica_txn_duration_s\":0.0,\"db_replica_duration_s\":0.0,\"db_primary_duration_s\":0.01,\"db_main_duration_s\":0.01,\"db_ci_duration_s\":0.0,\"db_main_replica_duration_s\":0.0,\"db_ci_replica_duration_s\":0.0,\"cpu_s\":0.047579,\"mem_objects\":32870,\"mem_bytes\":2376584,\"mem_mallocs\":11255,\"mem_total_bytes\":3691384,\"pid\":857,\"worker_id\":\"puma_master\",\"rate_limiting_gates\":[],\"db_duration_s\":0.00158,\"view_duration_s\":0.0,\"duration_s\":0.0242}",
        "provider": "RootController#index",
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
            "mem_bytes": 2376584,
            "mem_mallocs": 11255,
            "mem_objects": 32870,
            "mem_total_bytes": 3691384,
            "meta": {
                "client_id": "ip/",
                "feature_category": "groups_and_projects"
            },
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
            "inode": "119521725",
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
        "full": "http://example.org/users/sign_in",
        "path": "/"
    }
}
```