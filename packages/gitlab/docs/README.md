# GitLab Integration

This integration is for ingesting logs from [GitLab](https://about.gitlab.com/).

- `api`: Collect logs for HTTP requests made to the GitLab API

- `production`: Collect logs for Rails controller requests received from GitLab.

See the GitLab [Log system docs](https://docs.gitlab.com/ee/administration/logs/) for more information.

## Compatibility

The GitLab module has been developed with and tested against the [community edition](https://gitlab.com/rluna-gitlab/gitlab-ce) version 16.8.5-ce.0. 

## Setup

Refer to the GitLab documentation for the specific filepath(s) for your instance type. Both are provided as default in the configuration setup, but only one will be needed for use. See [API](https://docs.gitlab.com/ee/administration/logs/#api_jsonlog) and [Production](https://docs.gitlab.com/ee/administration/logs/#production_jsonlog) for details. 

## Logs

### api

Collect logs for HTTP requests made to the GitLab API. Check out the [GitLab API log docs](https://docs.gitlab.com/ee/administration/logs/#api_jsonlog) for more information.

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
| gitlab.api.correlation_id |  | keyword |
| gitlab.api.cpu_s |  | long |
| gitlab.api.db_cached_count |  | long |
| gitlab.api.db_ci_cached_count |  | long |
| gitlab.api.db_ci_count |  | long |
| gitlab.api.db_ci_duration_s |  | float |
| gitlab.api.db_ci_replica_cached_count |  | long |
| gitlab.api.db_ci_replica_count |  | long |
| gitlab.api.db_ci_replica_duration_s |  | float |
| gitlab.api.db_ci_replica_txn_count |  | long |
| gitlab.api.db_ci_replica_txn_duration_s |  | float |
| gitlab.api.db_ci_replica_wal_cached_count |  | long |
| gitlab.api.db_ci_replica_wal_count |  | long |
| gitlab.api.db_ci_txn_count |  | long |
| gitlab.api.db_ci_txn_duration_s |  | float |
| gitlab.api.db_ci_wal_cached_count |  | long |
| gitlab.api.db_ci_wal_count |  | long |
| gitlab.api.db_count |  | long |
| gitlab.api.db_duration_s |  | float |
| gitlab.api.db_main_cached_count |  | long |
| gitlab.api.db_main_count |  | long |
| gitlab.api.db_main_duration_s |  | float |
| gitlab.api.db_main_replica_cached_count |  | long |
| gitlab.api.db_main_replica_count |  | long |
| gitlab.api.db_main_replica_duration_s |  | float |
| gitlab.api.db_main_replica_txn_count |  | long |
| gitlab.api.db_main_replica_txn_duration_s |  | float |
| gitlab.api.db_main_replica_wal_cached_count |  | long |
| gitlab.api.db_main_replica_wal_count |  | long |
| gitlab.api.db_main_txn_count |  | long |
| gitlab.api.db_main_txn_duration_s |  | float |
| gitlab.api.db_main_wal_cached_count |  | long |
| gitlab.api.db_main_wal_count |  | long |
| gitlab.api.db_primary_cached_count |  | long |
| gitlab.api.db_primary_count |  | long |
| gitlab.api.db_primary_duration_s |  | float |
| gitlab.api.db_primary_txn_count |  | long |
| gitlab.api.db_primary_txn_duration_s |  | float |
| gitlab.api.db_primary_wal_cached_count |  | long |
| gitlab.api.db_primary_wal_count |  | long |
| gitlab.api.db_replica_cached_count |  | long |
| gitlab.api.db_replica_count |  | long |
| gitlab.api.db_replica_duration_s |  | float |
| gitlab.api.db_replica_txn_count |  | long |
| gitlab.api.db_replica_txn_duration_s |  | float |
| gitlab.api.db_replica_wal_cached_count |  | long |
| gitlab.api.db_replica_wal_count |  | long |
| gitlab.api.db_txn_count |  | long |
| gitlab.api.db_write_count |  | long |
| gitlab.api.duration_s |  | float |
| gitlab.api.mem_bytes |  | long |
| gitlab.api.mem_mallocs |  | long |
| gitlab.api.mem_objects |  | long |
| gitlab.api.mem_total_bytes |  | long |
| gitlab.api.meta.caller_id |  | keyword |
| gitlab.api.meta.client_id |  | keyword |
| gitlab.api.meta.feature_category |  | keyword |
| gitlab.api.meta.remote_ip |  | ip |
| gitlab.api.meta.user |  | keyword |
| gitlab.api.meta.user_id |  | long |
| gitlab.api.params.key |  | keyword |
| gitlab.api.params.value |  | keyword |
| gitlab.api.queue_duration_s |  | float |
| gitlab.api.redis_allowed_cross_slot_calls |  | long |
| gitlab.api.redis_cache_calls |  | long |
| gitlab.api.redis_cache_duration_s |  | float |
| gitlab.api.redis_cache_read_bytes |  | long |
| gitlab.api.redis_cache_write_bytes |  | long |
| gitlab.api.redis_calls |  | long |
| gitlab.api.redis_db_load_balancing_calls |  | long |
| gitlab.api.redis_db_load_balancing_duration_s |  | float |
| gitlab.api.redis_db_load_balancing_write_bytes |  | long |
| gitlab.api.redis_duration_s |  | float |
| gitlab.api.redis_feature_flag_calls |  | long |
| gitlab.api.redis_feature_flag_duration_s |  | float |
| gitlab.api.redis_feature_flag_read_bytes |  | long |
| gitlab.api.redis_feature_flag_write_bytes |  | long |
| gitlab.api.redis_read_bytes |  | long |
| gitlab.api.redis_sessions_allowed_cross_slot_calls |  | long |
| gitlab.api.redis_sessions_calls |  | long |
| gitlab.api.redis_sessions_duration_s |  | float |
| gitlab.api.redis_sessions_read_bytes |  | long |
| gitlab.api.redis_sessions_write_bytes |  | long |
| gitlab.api.redis_write_bytes |  | long |
| gitlab.api.request_urgency |  | keyword |
| gitlab.api.route |  | keyword |
| gitlab.api.target_duration_s |  | float |
| gitlab.api.time |  | keyword |
| gitlab.api.token_id |  | long |
| gitlab.api.token_type |  | keyword |
| gitlab.api.view_duration_s |  | float |
| gitlab.api.worker_id |  | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |


An example event for `api` looks as following:

```json
{
    "@timestamp": "2024-04-29T17:06:12.231Z",
    "agent": {
        "ephemeral_id": "9406e649-a731-4600-9b22-d80d322f078a",
        "id": "863c90df-5d95-44cd-a115-8c0972e2cb87",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.2"
    },
    "data_stream": {
        "dataset": "gitlab.api",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "863c90df-5d95-44cd-a115-8c0972e2cb87",
        "snapshot": false,
        "version": "8.13.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "api"
        ],
        "dataset": "gitlab.api",
        "duration": 19690,
        "ingested": "2024-05-21T18:17:53Z",
        "original": "{\"time\":\"2024-04-29T17:06:12.231Z\",\"severity\":\"INFO\",\"duration_s\":0.01969,\"db_duration_s\":0.0,\"view_duration_s\":0.01969,\"status\":200,\"method\":\"GET\",\"path\":\"/api/v4/geo/proxy\",\"params\":[],\"host\":\"localhost\",\"remote_ip\":\"127.0.0.1\",\"ua\":\"Go-http-client/1.1\",\"route\":\"/api/:version/geo/proxy\",\"db_count\":0,\"db_write_count\":0,\"db_cached_count\":0,\"db_txn_count\":0,\"db_replica_txn_count\":0,\"db_primary_txn_count\":0,\"db_main_txn_count\":0,\"db_ci_txn_count\":0,\"db_main_replica_txn_count\":0,\"db_ci_replica_txn_count\":0,\"db_replica_count\":0,\"db_primary_count\":0,\"db_main_count\":0,\"db_ci_count\":0,\"db_main_replica_count\":0,\"db_ci_replica_count\":0,\"db_replica_cached_count\":0,\"db_primary_cached_count\":0,\"db_main_cached_count\":0,\"db_ci_cached_count\":0,\"db_main_replica_cached_count\":0,\"db_ci_replica_cached_count\":0,\"db_replica_wal_count\":0,\"db_primary_wal_count\":0,\"db_main_wal_count\":0,\"db_ci_wal_count\":0,\"db_main_replica_wal_count\":0,\"db_ci_replica_wal_count\":0,\"db_replica_wal_cached_count\":0,\"db_primary_wal_cached_count\":0,\"db_main_wal_cached_count\":0,\"db_ci_wal_cached_count\":0,\"db_main_replica_wal_cached_count\":0,\"db_ci_replica_wal_cached_count\":0,\"db_replica_txn_duration_s\":0.0,\"db_primary_txn_duration_s\":0.0,\"db_main_txn_duration_s\":0.0,\"db_ci_txn_duration_s\":0.0,\"db_main_replica_txn_duration_s\":0.0,\"db_ci_replica_txn_duration_s\":0.0,\"db_replica_duration_s\":0.0,\"db_primary_duration_s\":0.0,\"db_main_duration_s\":0.0,\"db_ci_duration_s\":0.0,\"db_main_replica_duration_s\":0.0,\"db_ci_replica_duration_s\":0.0,\"cpu_s\":0.063617,\"mem_objects\":13367,\"mem_bytes\":1633512,\"mem_mallocs\":7711,\"mem_total_bytes\":2168192,\"pid\":1067,\"worker_id\":\"puma_4\",\"rate_limiting_gates\":[],\"correlation_id\":\"7ff5f562-f16f-4a93-b2ac-f771c81b0495\",\"meta.caller_id\":\"GET /api/:version/geo/proxy\",\"meta.remote_ip\":\"127.0.0.1\",\"meta.feature_category\":\"geo_replication\",\"meta.client_id\":\"ip/127.0.0.1\",\"request_urgency\":\"low\",\"target_duration_s\":5}",
        "provider": "GET /api/:version/geo/proxy",
        "type": [
            "info"
        ]
    },
    "gitlab": {
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
            "device_id": "35",
            "inode": "5815",
            "path": "/tmp/service_logs/test-gitlab-api.log"
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
        "gitlab-api"
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

Collect logs for Rails controller requests received from GitLab. Check out the [GitLab production log docs](https://docs.gitlab.com/ee/administration/logs/#production_jsonlog) for more information.

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
| gitlab.production.controller |  | keyword |
| gitlab.production.cpu_s |  | long |
| gitlab.production.db_cached_count |  | long |
| gitlab.production.db_ci_cached_count |  | long |
| gitlab.production.db_ci_count |  | long |
| gitlab.production.db_ci_duration_s |  | float |
| gitlab.production.db_ci_replica_cached_count |  | long |
| gitlab.production.db_ci_replica_count |  | long |
| gitlab.production.db_ci_replica_duration_s |  | float |
| gitlab.production.db_ci_replica_txn_count |  | long |
| gitlab.production.db_ci_replica_txn_duration_s |  | float |
| gitlab.production.db_ci_replica_wal_cached_count |  | long |
| gitlab.production.db_ci_replica_wal_count |  | long |
| gitlab.production.db_ci_txn_count |  | long |
| gitlab.production.db_ci_txn_duration_s |  | float |
| gitlab.production.db_ci_wal_cached_count |  | long |
| gitlab.production.db_ci_wal_count |  | long |
| gitlab.production.db_count |  | long |
| gitlab.production.db_duration_s |  | float |
| gitlab.production.db_main_cached_count |  | long |
| gitlab.production.db_main_count |  | long |
| gitlab.production.db_main_duration_s |  | float |
| gitlab.production.db_main_replica_cached_count |  | long |
| gitlab.production.db_main_replica_count |  | long |
| gitlab.production.db_main_replica_duration_s |  | float |
| gitlab.production.db_main_replica_txn_count |  | long |
| gitlab.production.db_main_replica_txn_duration_s |  | float |
| gitlab.production.db_main_replica_wal_cached_count |  | long |
| gitlab.production.db_main_replica_wal_count |  | long |
| gitlab.production.db_main_txn_count |  | long |
| gitlab.production.db_main_txn_duration_s |  | float |
| gitlab.production.db_main_wal_cached_count |  | long |
| gitlab.production.db_main_wal_count |  | long |
| gitlab.production.db_primary_cached_count |  | long |
| gitlab.production.db_primary_count |  | long |
| gitlab.production.db_primary_duration_s |  | float |
| gitlab.production.db_primary_txn_count |  | long |
| gitlab.production.db_primary_txn_duration_s |  | float |
| gitlab.production.db_primary_wal_cached_count |  | long |
| gitlab.production.db_primary_wal_count |  | long |
| gitlab.production.db_replica_cached_count |  | long |
| gitlab.production.db_replica_count |  | long |
| gitlab.production.db_replica_duration_s |  | float |
| gitlab.production.db_replica_txn_count |  | long |
| gitlab.production.db_replica_txn_duration_s |  | float |
| gitlab.production.db_replica_wal_cached_count |  | long |
| gitlab.production.db_replica_wal_count |  | long |
| gitlab.production.db_txn_count |  | long |
| gitlab.production.db_write_count |  | long |
| gitlab.production.format |  | keyword |
| gitlab.production.graphql.complexity |  | long |
| gitlab.production.graphql.depth |  | long |
| gitlab.production.graphql.operation_name |  | keyword |
| gitlab.production.graphql.used_deprecated_fields |  | keyword |
| gitlab.production.graphql.used_fields |  | keyword |
| gitlab.production.graphql.variables |  | keyword |
| gitlab.production.location |  | keyword |
| gitlab.production.mem_bytes |  | long |
| gitlab.production.mem_mallocs |  | long |
| gitlab.production.mem_objects |  | long |
| gitlab.production.mem_total_bytes |  | long |
| gitlab.production.meta.caller_id |  | keyword |
| gitlab.production.meta.client_id |  | keyword |
| gitlab.production.meta.feature_category |  | keyword |
| gitlab.production.meta.remote_ip |  | ip |
| gitlab.production.meta.search.page |  | keyword |
| gitlab.production.meta.user |  | keyword |
| gitlab.production.meta.user_id |  | long |
| gitlab.production.params.key |  | keyword |
| gitlab.production.params.value |  | keyword |
| gitlab.production.params.value_json.email |  | keyword |
| gitlab.production.params.value_json.first_name |  | keyword |
| gitlab.production.params.value_json.last_name |  | keyword |
| gitlab.production.params.value_json.login |  | keyword |
| gitlab.production.params.value_json.operationName |  | keyword |
| gitlab.production.params.value_json.password |  | keyword |
| gitlab.production.params.value_json.query |  | keyword |
| gitlab.production.params.value_json.remember_me |  | keyword |
| gitlab.production.params.value_json.username |  | keyword |
| gitlab.production.params.value_json.variables |  | keyword |
| gitlab.production.queue_duration_s |  | float |
| gitlab.production.rate_limiting_gates |  | keyword |
| gitlab.production.redis_allowed_cross_slot_calls |  | long |
| gitlab.production.redis_cache_calls |  | long |
| gitlab.production.redis_cache_duration_s |  | float |
| gitlab.production.redis_cache_read_bytes |  | long |
| gitlab.production.redis_cache_write_bytes |  | long |
| gitlab.production.redis_calls |  | long |
| gitlab.production.redis_db_load_balancing_calls |  | long |
| gitlab.production.redis_db_load_balancing_duration_s |  | float |
| gitlab.production.redis_db_load_balancing_write_bytes |  | long |
| gitlab.production.redis_duration_s |  | float |
| gitlab.production.redis_feature_flag_calls |  | long |
| gitlab.production.redis_feature_flag_duration_s |  | float |
| gitlab.production.redis_feature_flag_read_bytes |  | long |
| gitlab.production.redis_feature_flag_write_bytes |  | long |
| gitlab.production.redis_queues_calls |  | long |
| gitlab.production.redis_queues_duration_s |  | float |
| gitlab.production.redis_queues_metadata_calls |  | long |
| gitlab.production.redis_queues_metadata_duration_s |  | float |
| gitlab.production.redis_queues_metadata_read_bytes |  | long |
| gitlab.production.redis_queues_metadata_write_bytes |  | long |
| gitlab.production.redis_queues_read_bytes |  | long |
| gitlab.production.redis_queues_write_bytes |  | long |
| gitlab.production.redis_rate_limiting_calls |  | long |
| gitlab.production.redis_rate_limiting_duration_s |  | float |
| gitlab.production.redis_rate_limiting_read_bytes |  | long |
| gitlab.production.redis_rate_limiting_write_bytes |  | long |
| gitlab.production.redis_read_bytes |  | long |
| gitlab.production.redis_sessions_allowed_cross_slot_calls |  | long |
| gitlab.production.redis_sessions_calls |  | long |
| gitlab.production.redis_sessions_duration_s |  | float |
| gitlab.production.redis_sessions_read_bytes |  | long |
| gitlab.production.redis_sessions_write_bytes |  | long |
| gitlab.production.redis_shared_state_calls |  | long |
| gitlab.production.redis_shared_state_duration_s |  | float |
| gitlab.production.redis_shared_state_read_bytes |  | long |
| gitlab.production.redis_shared_state_write_bytes |  | long |
| gitlab.production.redis_write_bytes |  | long |
| gitlab.production.remote_ip |  | ip |
| gitlab.production.request_urgency |  | keyword |
| gitlab.production.target_duration_s |  | float |
| gitlab.production.time |  | keyword |
| gitlab.production.view_duration_s |  | float |
| gitlab.production.worker_id |  | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |


An example event for `production` looks as following:

```json
{
    "@timestamp": "2024-04-03T20:44:09.068Z",
    "agent": {
        "ephemeral_id": "bc5ad1cb-5294-48e2-99b6-6e23eed5520d",
        "id": "863c90df-5d95-44cd-a115-8c0972e2cb87",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.2"
    },
    "data_stream": {
        "dataset": "gitlab.production",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "863c90df-5d95-44cd-a115-8c0972e2cb87",
        "snapshot": false,
        "version": "8.13.2"
    },
    "event": {
        "action": "index",
        "agent_id_status": "verified",
        "dataset": "gitlab.production",
        "duration": 24200000,
        "id": "0bb7a10d-8da7-4499-8759-99ebe323f4b1",
        "ingested": "2024-05-21T18:25:47Z",
        "original": "{\"method\":\"GET\",\"path\":\"/\",\"format\":\"html\",\"controller\":\"RootController\",\"action\":\"index\",\"status\":302,\"location\":\"http://example.org/users/sign_in\",\"time\":\"2024-04-03T20:44:09.068Z\",\"params\":[],\"correlation_id\":\"0bb7a10d-8da7-4499-8759-99ebe323f4b1\",\"meta.caller_id\":\"RootController#index\",\"meta.feature_category\":\"groups_and_projects\",\"meta.client_id\":\"ip/\",\"request_urgency\":\"low\",\"target_duration_s\":5,\"redis_calls\":26,\"redis_duration_s\":0.005135,\"redis_read_bytes\":26,\"redis_write_bytes\":4284,\"redis_feature_flag_calls\":26,\"redis_feature_flag_duration_s\":0.005135,\"redis_feature_flag_read_bytes\":26,\"redis_feature_flag_write_bytes\":4284,\"db_count\":13,\"db_write_count\":0,\"db_cached_count\":0,\"db_txn_count\":0,\"db_replica_txn_count\":0,\"db_primary_txn_count\":0,\"db_main_txn_count\":0,\"db_ci_txn_count\":0,\"db_main_replica_txn_count\":0,\"db_ci_replica_txn_count\":0,\"db_replica_count\":0,\"db_primary_count\":13,\"db_main_count\":13,\"db_ci_count\":0,\"db_main_replica_count\":0,\"db_ci_replica_count\":0,\"db_replica_cached_count\":0,\"db_primary_cached_count\":0,\"db_main_cached_count\":0,\"db_ci_cached_count\":0,\"db_main_replica_cached_count\":0,\"db_ci_replica_cached_count\":0,\"db_replica_wal_count\":0,\"db_primary_wal_count\":0,\"db_main_wal_count\":0,\"db_ci_wal_count\":0,\"db_main_replica_wal_count\":0,\"db_ci_replica_wal_count\":0,\"db_replica_wal_cached_count\":0,\"db_primary_wal_cached_count\":0,\"db_main_wal_cached_count\":0,\"db_ci_wal_cached_count\":0,\"db_main_replica_wal_cached_count\":0,\"db_ci_replica_wal_cached_count\":0,\"db_replica_txn_duration_s\":0.0,\"db_primary_txn_duration_s\":0.0,\"db_main_txn_duration_s\":0.0,\"db_ci_txn_duration_s\":0.0,\"db_main_replica_txn_duration_s\":0.0,\"db_ci_replica_txn_duration_s\":0.0,\"db_replica_duration_s\":0.0,\"db_primary_duration_s\":0.01,\"db_main_duration_s\":0.01,\"db_ci_duration_s\":0.0,\"db_main_replica_duration_s\":0.0,\"db_ci_replica_duration_s\":0.0,\"cpu_s\":0.047579,\"mem_objects\":32870,\"mem_bytes\":2376584,\"mem_mallocs\":11255,\"mem_total_bytes\":3691384,\"pid\":857,\"worker_id\":\"puma_master\",\"rate_limiting_gates\":[],\"db_duration_s\":0.00158,\"view_duration_s\":0.0,\"duration_s\":0.0242}",
        "provider": "RootController#index",
        "type": [
            "info"
        ]
    },
    "gitlab": {
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
            "device_id": "35",
            "inode": "5848",
            "path": "/tmp/service_logs/test-gitlab-production.log"
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
        "gitlab-production"
    ],
    "url": {
        "full": "http://example.org/users/sign_in",
        "path": "/"
    }
}
```