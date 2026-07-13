# GitLab Integration

This integration is for ingesting logs from [GitLab](https://about.gitlab.com/).

- **api**: Collect logs for HTTP requests made to the GitLab API

- **application**: Collect logs for events in GitLab like user creation or project deletion.

- **audit**: Collect logs for changes to group or project settings and memberships.

- **auth**: Collect logs for protected paths abusive requests or requests over the Rate Limit.

- **pages**: Collect logs for Pages.

- **production**: Collect logs for Rails controller requests received from GitLab.

- **sidekiq**: Collect logs from [sidekiq](https://sidekiq.org/) for jobs background jobs that take a long time.

See the GitLab [Log system docs](https://docs.gitlab.com/ee/administration/logs/) for more information.

## Compatibility

The GitLab module has been developed with and tested against the [community edition](https://gitlab.com/rluna-gitlab/gitlab-ce) version 18.9.2-ce.0. 

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

Refer to the [GitLab documentation](https://docs.gitlab.com/ee/administration/logs/) for the specific filepath(s) for your instance type. Both are provided as default in the configuration setup, but only one will be needed for use.

## Logs

### api

Collect logs for HTTP requests made to the GitLab API. Check out the [GitLab API log docs](https://docs.gitlab.com/ee/administration/logs/#api_jsonlog) for more information.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| gitlab.api.api_error |  | flattened |
| gitlab.api.content_length |  | long |
| gitlab.api.correlation_id |  | keyword |
| gitlab.api.cpu_s |  | long |
| gitlab.api.db |  | double |
| gitlab.api.db_cached_count |  | long |
| gitlab.api.db_ci_cached_count |  | long |
| gitlab.api.db_ci_count |  | long |
| gitlab.api.db_ci_duration_s |  | float |
| gitlab.api.db_ci_replica_cached_count |  | long |
| gitlab.api.db_ci_replica_count |  | long |
| gitlab.api.db_ci_replica_duration_s |  | float |
| gitlab.api.db_ci_replica_txn_count |  | long |
| gitlab.api.db_ci_replica_txn_duration_s |  | float |
| gitlab.api.db_ci_replica_txn_max_duration_s |  | double |
| gitlab.api.db_ci_replica_wal_cached_count |  | long |
| gitlab.api.db_ci_replica_wal_count |  | long |
| gitlab.api.db_ci_replica_write_count |  | long |
| gitlab.api.db_ci_txn_count |  | long |
| gitlab.api.db_ci_txn_duration_s |  | float |
| gitlab.api.db_ci_txn_max_duration_s |  | double |
| gitlab.api.db_ci_wal_cached_count |  | long |
| gitlab.api.db_ci_wal_count |  | long |
| gitlab.api.db_ci_write_count |  | long |
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
| gitlab.api.db_main_replica_txn_max_duration_s |  | double |
| gitlab.api.db_main_replica_wal_cached_count |  | long |
| gitlab.api.db_main_replica_wal_count |  | long |
| gitlab.api.db_main_replica_write_count |  | long |
| gitlab.api.db_main_txn_count |  | long |
| gitlab.api.db_main_txn_duration_s |  | float |
| gitlab.api.db_main_txn_max_duration_s |  | double |
| gitlab.api.db_main_wal_cached_count |  | long |
| gitlab.api.db_main_wal_count |  | long |
| gitlab.api.db_main_write_count |  | long |
| gitlab.api.db_primary_cached_count |  | long |
| gitlab.api.db_primary_count |  | long |
| gitlab.api.db_primary_duration_s |  | float |
| gitlab.api.db_primary_txn_count |  | long |
| gitlab.api.db_primary_txn_duration_s |  | float |
| gitlab.api.db_primary_txn_max_duration_s |  | double |
| gitlab.api.db_primary_wal_cached_count |  | long |
| gitlab.api.db_primary_wal_count |  | long |
| gitlab.api.db_primary_write_count |  | long |
| gitlab.api.db_replica_cached_count |  | long |
| gitlab.api.db_replica_count |  | long |
| gitlab.api.db_replica_duration_s |  | float |
| gitlab.api.db_replica_txn_count |  | long |
| gitlab.api.db_replica_txn_duration_s |  | float |
| gitlab.api.db_replica_txn_max_duration_s |  | double |
| gitlab.api.db_replica_wal_cached_count |  | long |
| gitlab.api.db_replica_wal_count |  | long |
| gitlab.api.db_replica_write_count |  | long |
| gitlab.api.db_txn_count |  | long |
| gitlab.api.db_write_count |  | long |
| gitlab.api.duration |  | float |
| gitlab.api.duration_s |  | float |
| gitlab.api.exclusive_lock_hold_duration_s |  | double |
| gitlab.api.exclusive_lock_requested_count |  | long |
| gitlab.api.exclusive_lock_wait_duration_s |  | double |
| gitlab.api.gitaly_calls |  | long |
| gitlab.api.gitaly_duration |  | float |
| gitlab.api.gitaly_duration_s |  | double |
| gitlab.api.host |  | keyword |
| gitlab.api.mem_bytes |  | long |
| gitlab.api.mem_mallocs |  | long |
| gitlab.api.mem_objects |  | long |
| gitlab.api.mem_total_bytes |  | long |
| gitlab.api.meta.caller_id |  | keyword |
| gitlab.api.meta.client_id |  | keyword |
| gitlab.api.meta.feature_category |  | keyword |
| gitlab.api.meta.gl_user_id |  | keyword |
| gitlab.api.meta.organization_id |  | keyword |
| gitlab.api.meta.project |  | keyword |
| gitlab.api.meta.remote_ip |  | ip |
| gitlab.api.meta.root_namespace |  | keyword |
| gitlab.api.meta.user |  | keyword |
| gitlab.api.meta.user_id |  | long |
| gitlab.api.params.action |  | keyword |
| gitlab.api.params.changes |  | keyword |
| gitlab.api.params.info.architecture |  | keyword |
| gitlab.api.params.info.executor |  | keyword |
| gitlab.api.params.info.features.raw_variables |  | keyword |
| gitlab.api.params.info.features.service_variables |  | keyword |
| gitlab.api.params.info.features.trace_checksum |  | keyword |
| gitlab.api.params.info.features.trace_reset |  | keyword |
| gitlab.api.params.info.features.variables |  | keyword |
| gitlab.api.params.info.features.vault_secrets |  | keyword |
| gitlab.api.params.info.name |  | keyword |
| gitlab.api.params.info.platform |  | keyword |
| gitlab.api.params.info.revision |  | keyword |
| gitlab.api.params.info.version |  | keyword |
| gitlab.api.params.key |  | keyword |
| gitlab.api.params.key_id |  | keyword |
| gitlab.api.params.last_update |  | keyword |
| gitlab.api.params.name |  | keyword |
| gitlab.api.params.private_token |  | keyword |
| gitlab.api.params.secret_token |  | keyword |
| gitlab.api.params.system_id |  | keyword |
| gitlab.api.params.token |  | keyword |
| gitlab.api.params.value |  | keyword |
| gitlab.api.path |  | keyword |
| gitlab.api.path_traversal_check_duration_s |  | double |
| gitlab.api.pid |  | keyword |
| gitlab.api.queue_duration |  | float |
| gitlab.api.queue_duration_s |  | float |
| gitlab.api.redis_allowed_cross_slot_calls |  | long |
| gitlab.api.redis_cache_calls |  | long |
| gitlab.api.redis_cache_duration_s |  | double |
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
| gitlab.api.redis_queues_calls |  | long |
| gitlab.api.redis_queues_duration_s |  | double |
| gitlab.api.redis_queues_metadata_calls |  | long |
| gitlab.api.redis_queues_metadata_duration_s |  | double |
| gitlab.api.redis_queues_metadata_read_bytes |  | long |
| gitlab.api.redis_queues_metadata_write_bytes |  | long |
| gitlab.api.redis_queues_read_bytes |  | long |
| gitlab.api.redis_queues_write_bytes |  | long |
| gitlab.api.redis_rate_limiting_calls |  | long |
| gitlab.api.redis_rate_limiting_duration_s |  | double |
| gitlab.api.redis_rate_limiting_read_bytes |  | long |
| gitlab.api.redis_rate_limiting_write_bytes |  | long |
| gitlab.api.redis_read_bytes |  | long |
| gitlab.api.redis_repository_cache_allowed_cross_slot_calls |  | long |
| gitlab.api.redis_repository_cache_calls |  | long |
| gitlab.api.redis_repository_cache_duration_s |  | double |
| gitlab.api.redis_repository_cache_read_bytes |  | long |
| gitlab.api.redis_repository_cache_write_bytes |  | long |
| gitlab.api.redis_sessions_allowed_cross_slot_calls |  | long |
| gitlab.api.redis_sessions_calls |  | long |
| gitlab.api.redis_sessions_duration_s |  | float |
| gitlab.api.redis_sessions_read_bytes |  | long |
| gitlab.api.redis_sessions_write_bytes |  | long |
| gitlab.api.redis_shared_state_calls |  | long |
| gitlab.api.redis_shared_state_duration_s |  | double |
| gitlab.api.redis_shared_state_read_bytes |  | long |
| gitlab.api.redis_shared_state_write_bytes |  | long |
| gitlab.api.redis_write_bytes |  | long |
| gitlab.api.request_urgency |  | keyword |
| gitlab.api.route |  | keyword |
| gitlab.api.target_duration_s |  | float |
| gitlab.api.time |  | keyword |
| gitlab.api.token_id |  | long |
| gitlab.api.token_type |  | keyword |
| gitlab.api.view |  | double |
| gitlab.api.view_duration_s |  | float |
| gitlab.api.worker_id |  | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |


An example event for `api` looks as following:

```json
{
    "@timestamp": "2024-04-29T17:06:12.231Z",
    "agent": {
        "ephemeral_id": "f0e9557d-9155-4d37-87b7-76055ffa39bc",
        "id": "f9f8a814-dfcd-43c7-a86e-af6adaf2287e",
        "name": "elastic-agent-20638",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "gitlab.api",
        "namespace": "40136",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "f9f8a814-dfcd-43c7-a86e-af6adaf2287e",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "api"
        ],
        "dataset": "gitlab.api",
        "duration": 19690,
        "ingested": "2026-03-30T12:12:59Z",
        "kind": "event",
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
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "elastic-agent-20638",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.241.2",
            "192.168.240.7"
        ],
        "mac": [
            "2A-FE-08-2F-FD-10",
            "56-3D-E0-9C-4A-D5"
        ],
        "name": "localhost",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.15.0-173-generic",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
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
            "device_id": "64768",
            "inode": "547212",
            "path": "/tmp/service_logs/test-gitlab-api.log"
        },
        "level": "INFO",
        "offset": 0
    },
    "process": {
        "pid": 1067
    },
    "related": {
        "hosts": [
            "localhost"
        ],
        "ip": [
            "127.0.0.1"
        ]
    },
    "source": {
        "ip": [
            "127.0.0.1"
        ]
    },
    "tags": [
        "preserve_original_event",
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

### application

Collect logs for events happening in GitLab like user creation or project deletion. Check out the [GitLab Application log docs](https://docs.gitlab.com/ee/administration/logs/#application_jsonlog) for more information.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| gitlab.application.attributes |  | keyword |
| gitlab.application.caller |  | keyword |
| gitlab.application.class |  | keyword |
| gitlab.application.class_name |  | keyword |
| gitlab.application.connection_name |  | keyword |
| gitlab.application.correlation_id |  | keyword |
| gitlab.application.current_iteration |  | long |
| gitlab.application.duration_s |  | double |
| gitlab.application.event |  | keyword |
| gitlab.application.from_state |  | keyword |
| gitlab.application.lease_key |  | keyword |
| gitlab.application.lease_timeout |  | long |
| gitlab.application.lock_timeout_in_ms |  | long |
| gitlab.application.login_method |  | keyword |
| gitlab.application.mail_subject |  | keyword |
| gitlab.application.memwd_cur_strikes |  | long |
| gitlab.application.memwd_handler_class |  | keyword |
| gitlab.application.memwd_max_rss_bytes |  | long |
| gitlab.application.memwd_max_strikes |  | long |
| gitlab.application.memwd_reason |  | keyword |
| gitlab.application.memwd_rss_bytes |  | long |
| gitlab.application.memwd_sleep_time_s |  | long |
| gitlab.application.merge_request_info |  | keyword |
| gitlab.application.mergeability.check_approved_service.db_cached_count |  | long |
| gitlab.application.mergeability.check_approved_service.db_count |  | long |
| gitlab.application.mergeability.check_approved_service.db_main_cached_count |  | long |
| gitlab.application.mergeability.check_approved_service.db_main_count |  | long |
| gitlab.application.mergeability.check_approved_service.db_main_duration_s |  | long |
| gitlab.application.mergeability.check_approved_service.db_primary_cached_count |  | long |
| gitlab.application.mergeability.check_approved_service.db_primary_count |  | long |
| gitlab.application.mergeability.check_approved_service.db_primary_duration_s |  | long |
| gitlab.application.mergeability.check_approved_service.duration_s |  | long |
| gitlab.application.mergeability.check_approved_service.successful |  | boolean |
| gitlab.application.mergeability.check_blocked_by_other_mrs_service.db_cached_count |  | long |
| gitlab.application.mergeability.check_blocked_by_other_mrs_service.db_count |  | long |
| gitlab.application.mergeability.check_blocked_by_other_mrs_service.db_main_cached_count |  | long |
| gitlab.application.mergeability.check_blocked_by_other_mrs_service.db_main_count |  | long |
| gitlab.application.mergeability.check_blocked_by_other_mrs_service.db_main_duration_s |  | long |
| gitlab.application.mergeability.check_blocked_by_other_mrs_service.db_primary_cached_count |  | long |
| gitlab.application.mergeability.check_blocked_by_other_mrs_service.db_primary_count |  | long |
| gitlab.application.mergeability.check_blocked_by_other_mrs_service.db_primary_duration_s |  | long |
| gitlab.application.mergeability.check_blocked_by_other_mrs_service.duration_s |  | long |
| gitlab.application.mergeability.check_blocked_by_other_mrs_service.successful |  | boolean |
| gitlab.application.mergeability.check_broken_status_service.db_cached_count |  | long |
| gitlab.application.mergeability.check_broken_status_service.db_count |  | long |
| gitlab.application.mergeability.check_broken_status_service.db_main_cached_count |  | long |
| gitlab.application.mergeability.check_broken_status_service.db_main_count |  | long |
| gitlab.application.mergeability.check_broken_status_service.db_main_duration_s |  | long |
| gitlab.application.mergeability.check_broken_status_service.db_primary_cached_count |  | long |
| gitlab.application.mergeability.check_broken_status_service.db_primary_count |  | long |
| gitlab.application.mergeability.check_broken_status_service.db_primary_duration_s |  | long |
| gitlab.application.mergeability.check_broken_status_service.duration_s |  | long |
| gitlab.application.mergeability.check_broken_status_service.successful |  | boolean |
| gitlab.application.mergeability.check_ci_status_service.duration_s |  | long |
| gitlab.application.mergeability.check_ci_status_service.successful |  | boolean |
| gitlab.application.mergeability.check_commits_status_service.duration_s |  | long |
| gitlab.application.mergeability.check_commits_status_service.successful |  | boolean |
| gitlab.application.mergeability.check_conflict_status_service.duration_s |  | long |
| gitlab.application.mergeability.check_conflict_status_service.successful |  | boolean |
| gitlab.application.mergeability.check_discussions_status_service.db_cached_count |  | long |
| gitlab.application.mergeability.check_discussions_status_service.db_count |  | long |
| gitlab.application.mergeability.check_discussions_status_service.db_main_cached_count |  | long |
| gitlab.application.mergeability.check_discussions_status_service.db_main_count |  | long |
| gitlab.application.mergeability.check_discussions_status_service.db_primary_cached_count |  | long |
| gitlab.application.mergeability.check_discussions_status_service.db_primary_count |  | long |
| gitlab.application.mergeability.check_discussions_status_service.duration_s |  | long |
| gitlab.application.mergeability.check_discussions_status_service.successful |  | boolean |
| gitlab.application.mergeability.check_draft_status_service.duration_s |  | long |
| gitlab.application.mergeability.check_draft_status_service.successful |  | boolean |
| gitlab.application.mergeability.check_external_status_checks_passed_service.db_cached_count |  | long |
| gitlab.application.mergeability.check_external_status_checks_passed_service.db_count |  | long |
| gitlab.application.mergeability.check_external_status_checks_passed_service.db_main_cached_count |  | long |
| gitlab.application.mergeability.check_external_status_checks_passed_service.db_main_count |  | long |
| gitlab.application.mergeability.check_external_status_checks_passed_service.db_main_duration_s |  | long |
| gitlab.application.mergeability.check_external_status_checks_passed_service.db_primary_cached_count |  | long |
| gitlab.application.mergeability.check_external_status_checks_passed_service.db_primary_count |  | long |
| gitlab.application.mergeability.check_external_status_checks_passed_service.db_primary_duration_s |  | long |
| gitlab.application.mergeability.check_external_status_checks_passed_service.duration_s |  | long |
| gitlab.application.mergeability.check_external_status_checks_passed_service.successful |  | boolean |
| gitlab.application.mergeability.check_jira_status_service.db_cached_count |  | long |
| gitlab.application.mergeability.check_jira_status_service.db_count |  | long |
| gitlab.application.mergeability.check_jira_status_service.db_main_cached_count |  | long |
| gitlab.application.mergeability.check_jira_status_service.db_main_count |  | long |
| gitlab.application.mergeability.check_jira_status_service.db_primary_cached_count |  | long |
| gitlab.application.mergeability.check_jira_status_service.db_primary_count |  | long |
| gitlab.application.mergeability.check_jira_status_service.duration_s |  | long |
| gitlab.application.mergeability.check_jira_status_service.successful |  | boolean |
| gitlab.application.mergeability.check_open_status_service.duration_s |  | long |
| gitlab.application.mergeability.check_open_status_service.successful |  | boolean |
| gitlab.application.mergeability.check_rebase_status_service.duration_s |  | long |
| gitlab.application.mergeability.check_rebase_status_service.successful |  | boolean |
| gitlab.application.mergeability.merge_request_id |  | long |
| gitlab.application.mergeability.project_id |  | long |
| gitlab.application.message |  | keyword |
| gitlab.application.meta.caller_id |  | keyword |
| gitlab.application.meta.client_id |  | keyword |
| gitlab.application.meta.feature_category |  | keyword |
| gitlab.application.meta.gl_user_id |  | keyword |
| gitlab.application.meta.organization_id |  | keyword |
| gitlab.application.meta.project |  | keyword |
| gitlab.application.meta.remote_ip |  | ip |
| gitlab.application.meta.root_caller_id |  | keyword |
| gitlab.application.meta.root_namespace |  | keyword |
| gitlab.application.meta.user |  | keyword |
| gitlab.application.meta.user_id |  | long |
| gitlab.application.method |  | keyword |
| gitlab.application.model |  | keyword |
| gitlab.application.model_connection_name |  | keyword |
| gitlab.application.model_id |  | long |
| gitlab.application.namespace_id |  | long |
| gitlab.application.partition_name |  | keyword |
| gitlab.application.pid |  | long |
| gitlab.application.project_id |  | long |
| gitlab.application.project_name |  | keyword |
| gitlab.application.runtime |  | keyword |
| gitlab.application.severity |  | keyword |
| gitlab.application.shared_connection_name |  | keyword |
| gitlab.application.silent_mode_enabled |  | boolean |
| gitlab.application.table_name |  | keyword |
| gitlab.application.time |  | date |
| gitlab.application.to_state |  | keyword |
| gitlab.application.user_admin |  | boolean |
| gitlab.application.user_id |  | long |
| gitlab.application.worker_id |  | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Log offset | long |


An example event for `application` looks as following:

```json
{
    "@timestamp": "2024-05-10T17:49:45.825Z",
    "agent": {
        "ephemeral_id": "81eaa642-e005-47c4-a0ba-a520c4107322",
        "id": "aea61476-76a6-4bea-8069-596da60fa919",
        "name": "elastic-agent-29703",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "client": {
        "address": "67.43.156.18",
        "as": {
            "number": 35908
        },
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.18"
    },
    "data_stream": {
        "dataset": "gitlab.application",
        "namespace": "33978",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "aea61476-76a6-4bea-8069-596da60fa919",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "dataset": "gitlab.application",
        "id": "01HXHSYJJQNY08JV4JF2B69ZDR",
        "ingested": "2026-03-31T05:58:59Z",
        "kind": "event",
        "original": "{\"severity\":\"INFO\",\"time\":\"2024-05-10T17:49:45.825Z\",\"correlation_id\":\"01HXHSYJJQNY08JV4JF2B69ZDR\",\"meta.caller_id\":\"ProjectCacheWorker\",\"meta.remote_ip\":\"67.43.156.18\",\"meta.feature_category\":\"source_code_management\",\"meta.user\":\"root\",\"meta.user_id\":1,\"meta.project\":\"root/test_1\",\"meta.root_namespace\":\"root\",\"meta.client_id\":\"user/1\",\"meta.root_caller_id\":\"ProjectsController#create\",\"message\":\"Updating statistics for project 1\"}",
        "severity": 1,
        "type": [
            "info"
        ]
    },
    "gitlab": {
        "application": {
            "message": "Updating statistics for project 1",
            "meta": {
                "caller_id": "ProjectCacheWorker",
                "client_id": "user/1",
                "feature_category": "source_code_management",
                "project": "root/test_1",
                "root_caller_id": "ProjectsController#create",
                "root_namespace": "root"
            }
        }
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "elastic-agent-29703",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.241.2",
            "192.168.240.7"
        ],
        "mac": [
            "96-31-7B-A5-EF-9A",
            "A2-25-2E-2B-26-E3"
        ],
        "name": "elastic-agent-29703",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.15.0-173-generic",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "device_id": "64768",
            "inode": "561421",
            "path": "/tmp/service_logs/test-gitlab-application.log"
        },
        "offset": 0
    },
    "related": {
        "ip": [
            "67.43.156.18"
        ],
        "user": [
            "1",
            "root"
        ]
    },
    "source": {
        "address": "67.43.156.18",
        "as": {
            "number": 35908
        },
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.18"
    },
    "tags": [
        "preserve_original_event",
        "gitlab-application"
    ],
    "user": {
        "id": "1",
        "name": "root"
    }
}
```

### audit

Collect logs for changes to group or project settings and memberships. Check out the [GitLab Audit log docs](https://docs.gitlab.com/ee/administration/logs/#audit_jsonlog) for more information.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| gitlab.audit.change |  | keyword |
| gitlab.audit.created_at |  | date |
| gitlab.audit.entity_id |  | long |
| gitlab.audit.entity_type |  | keyword |
| gitlab.audit.from |  | keyword |
| gitlab.audit.meta.caller_id |  | keyword |
| gitlab.audit.meta.client_id |  | keyword |
| gitlab.audit.meta.feature_category |  | keyword |
| gitlab.audit.meta.project |  | keyword |
| gitlab.audit.meta.remote_ip |  | ip |
| gitlab.audit.meta.root_namespace |  | keyword |
| gitlab.audit.meta.user |  | keyword |
| gitlab.audit.meta.user_id |  | long |
| gitlab.audit.target_details |  | keyword |
| gitlab.audit.target_id |  | long |
| gitlab.audit.target_type |  | keyword |
| gitlab.audit.to |  | keyword |
| gitlab.audit.with |  | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Log offset | long |


An example event for `audit` looks as following:

```json
{
    "@timestamp": "2018-10-17T17:38:22.523Z",
    "agent": {
        "ephemeral_id": "1a5bfab6-301c-4979-8a04-e6296dc2a2c9",
        "id": "9b3816b9-e0ec-44e8-8833-d96b1e4e3d9c",
        "name": "elastic-agent-99622",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "gitlab.audit",
        "namespace": "78162",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9b3816b9-e0ec-44e8-8833-d96b1e4e3d9c",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "gitlab.audit",
        "ingested": "2026-03-30T07:12:49Z",
        "kind": "event",
        "original": "{\"severity\": \"INFO\",\"time\": \"2018-10-17T17:38:22.523Z\",\"author_id\": 3,\"entity_id\": 2,\"entity_type\": \"Project\",\"change\": \"visibility\",\"from\": \"Private\",\"to\": \"Public\",\"author_name\": \"John Doe4\",\"target_id\": 2,\"target_type\": \"Project\",\"target_details\": \"namespace2/project2\"}",
        "severity": 1,
        "type": [
            "info"
        ]
    },
    "gitlab": {
        "audit": {
            "change": "visibility",
            "entity_id": 2,
            "entity_type": "Project",
            "from": "Private",
            "target_details": "namespace2/project2",
            "target_id": 2,
            "target_type": "Project",
            "to": "Public"
        }
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "elastic-agent-99622",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.241.2",
            "192.168.240.7"
        ],
        "mac": [
            "22-99-6D-ED-3E-ED",
            "CA-65-E6-92-0C-22"
        ],
        "name": "elastic-agent-99622",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.15.0-173-generic",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "device_id": "64768",
            "inode": "547126",
            "path": "/tmp/service_logs/test-gitlab-audit.log"
        },
        "offset": 507
    },
    "related": {
        "user": [
            "3",
            "John Doe4"
        ]
    },
    "tags": [
        "preserve_original_event",
        "gitlab-audit"
    ],
    "user": {
        "id": "3",
        "name": "John Doe4"
    }
}
```

### auth

Collect logs for abusive protect paths requests or requests over the Rate Limit. Check out the [GitLab Auth log docs](https://docs.gitlab.com/ee/administration/logs/#auth_jsonlog) for more information.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| gitlab.auth.controller |  | keyword |
| gitlab.auth.cpu_s |  | long |
| gitlab.auth.db_cached_count |  | long |
| gitlab.auth.db_ci_cached_count |  | long |
| gitlab.auth.db_ci_count |  | long |
| gitlab.auth.db_ci_duration_s |  | float |
| gitlab.auth.db_ci_replica_cached_count |  | long |
| gitlab.auth.db_ci_replica_count |  | long |
| gitlab.auth.db_ci_replica_duration_s |  | float |
| gitlab.auth.db_ci_replica_txn_count |  | long |
| gitlab.auth.db_ci_replica_txn_duration_s |  | float |
| gitlab.auth.db_ci_replica_wal_cached_count |  | long |
| gitlab.auth.db_ci_replica_wal_count |  | long |
| gitlab.auth.db_ci_txn_count |  | long |
| gitlab.auth.db_ci_txn_duration_s |  | float |
| gitlab.auth.db_ci_wal_cached_count |  | long |
| gitlab.auth.db_ci_wal_count |  | long |
| gitlab.auth.db_count |  | long |
| gitlab.auth.db_duration_s |  | float |
| gitlab.auth.db_main_cached_count |  | long |
| gitlab.auth.db_main_count |  | long |
| gitlab.auth.db_main_duration_s |  | float |
| gitlab.auth.db_main_replica_cached_count |  | long |
| gitlab.auth.db_main_replica_count |  | long |
| gitlab.auth.db_main_replica_duration_s |  | float |
| gitlab.auth.db_main_replica_txn_count |  | long |
| gitlab.auth.db_main_replica_txn_duration_s |  | float |
| gitlab.auth.db_main_replica_wal_cached_count |  | long |
| gitlab.auth.db_main_replica_wal_count |  | long |
| gitlab.auth.db_main_txn_count |  | long |
| gitlab.auth.db_main_txn_duration_s |  | float |
| gitlab.auth.db_main_wal_cached_count |  | long |
| gitlab.auth.db_main_wal_count |  | long |
| gitlab.auth.db_primary_cached_count |  | long |
| gitlab.auth.db_primary_count |  | long |
| gitlab.auth.db_primary_duration_s |  | float |
| gitlab.auth.db_primary_txn_count |  | long |
| gitlab.auth.db_primary_txn_duration_s |  | float |
| gitlab.auth.db_primary_wal_cached_count |  | long |
| gitlab.auth.db_primary_wal_count |  | long |
| gitlab.auth.db_replica_cached_count |  | long |
| gitlab.auth.db_replica_count |  | long |
| gitlab.auth.db_replica_duration_s |  | float |
| gitlab.auth.db_replica_txn_count |  | long |
| gitlab.auth.db_replica_txn_duration_s |  | float |
| gitlab.auth.db_replica_wal_cached_count |  | long |
| gitlab.auth.db_replica_wal_count |  | long |
| gitlab.auth.db_txn_count |  | long |
| gitlab.auth.db_write_count |  | long |
| gitlab.auth.env |  | keyword |
| gitlab.auth.format |  | keyword |
| gitlab.auth.location |  | keyword |
| gitlab.auth.matched |  | keyword |
| gitlab.auth.mem_bytes |  | long |
| gitlab.auth.mem_mallocs |  | long |
| gitlab.auth.mem_objects |  | long |
| gitlab.auth.mem_total_bytes |  | long |
| gitlab.auth.message |  | keyword |
| gitlab.auth.meta.user |  | keyword |
| gitlab.auth.rate_limiting_gates |  | keyword |
| gitlab.auth.redis_allowed_cross_slot_calls |  | long |
| gitlab.auth.redis_cache_calls |  | long |
| gitlab.auth.redis_cache_duration_s |  | double |
| gitlab.auth.redis_cache_read_bytes |  | long |
| gitlab.auth.redis_cache_write_bytes |  | long |
| gitlab.auth.redis_calls |  | long |
| gitlab.auth.redis_db_load_balancing_calls |  | long |
| gitlab.auth.redis_db_load_balancing_duration_s |  | float |
| gitlab.auth.redis_db_load_balancing_write_bytes |  | long |
| gitlab.auth.redis_duration_s |  | float |
| gitlab.auth.redis_feature_flag_calls |  | long |
| gitlab.auth.redis_feature_flag_duration_s |  | float |
| gitlab.auth.redis_feature_flag_read_bytes |  | long |
| gitlab.auth.redis_feature_flag_write_bytes |  | long |
| gitlab.auth.redis_queues_calls |  | long |
| gitlab.auth.redis_queues_duration_s |  | float |
| gitlab.auth.redis_queues_metadata_calls |  | long |
| gitlab.auth.redis_queues_metadata_duration_s |  | float |
| gitlab.auth.redis_queues_metadata_read_bytes |  | long |
| gitlab.auth.redis_queues_metadata_write_bytes |  | long |
| gitlab.auth.redis_queues_read_bytes |  | long |
| gitlab.auth.redis_queues_write_bytes |  | long |
| gitlab.auth.redis_rate_limiting_calls |  | long |
| gitlab.auth.redis_rate_limiting_duration_s |  | float |
| gitlab.auth.redis_rate_limiting_read_bytes |  | long |
| gitlab.auth.redis_rate_limiting_write_bytes |  | long |
| gitlab.auth.redis_read_bytes |  | long |
| gitlab.auth.redis_sessions_allowed_cross_slot_calls |  | long |
| gitlab.auth.redis_sessions_calls |  | long |
| gitlab.auth.redis_sessions_duration_s |  | float |
| gitlab.auth.redis_sessions_read_bytes |  | long |
| gitlab.auth.redis_sessions_write_bytes |  | long |
| gitlab.auth.redis_shared_state_calls |  | long |
| gitlab.auth.redis_shared_state_duration_s |  | float |
| gitlab.auth.redis_shared_state_read_bytes |  | long |
| gitlab.auth.redis_shared_state_write_bytes |  | long |
| gitlab.auth.redis_write_bytes |  | long |
| gitlab.auth.remote_ip |  | ip |
| gitlab.auth.request_urgency |  | keyword |
| gitlab.auth.time |  | keyword |
| gitlab.auth.worker_id |  | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Log offset | long |


An example event for `auth` looks as following:

```json
{
    "@timestamp": "2023-04-19T22:14:25.893Z",
    "agent": {
        "ephemeral_id": "0cc599fd-fe51-44b1-b45b-134cc24e2059",
        "id": "dd70f9ae-e610-4415-b0e3-9ac90d09dfd7",
        "name": "elastic-agent-21583",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "client": {
        "address": "67.43.156.18",
        "as": {
            "number": 35908
        },
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.18"
    },
    "data_stream": {
        "dataset": "gitlab.auth",
        "namespace": "45646",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "dd70f9ae-e610-4415-b0e3-9ac90d09dfd7",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "gitlab.auth",
        "id": "01GYDSAKAN2SPZPAMJNRWW5H8S",
        "ingested": "2026-03-30T07:13:38Z",
        "kind": "event",
        "original": "{\"severity\": \"ERROR\",\"time\": \"2023-04-19T22:14:25.893Z\",\"correlation_id\": \"01GYDSAKAN2SPZPAMJNRWW5H8S\",\"message\": \"Rack_Attack\",\"env\": \"blocklist\",\"remote_ip\": \"67.43.156.18\",\"request_method\": \"GET\",\"path\": \"/group/project.git/info/refs?service=git-upload-pack\"}",
        "severity": 3,
        "type": [
            "info"
        ]
    },
    "gitlab": {
        "auth": {
            "env": "blocklist",
            "message": "Rack_Attack"
        }
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "elastic-agent-21583",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.241.2",
            "192.168.240.7"
        ],
        "mac": [
            "02-16-BC-F2-F4-FB",
            "E6-42-16-88-F6-06"
        ],
        "name": "elastic-agent-21583",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.15.0-173-generic",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "http": {
        "request": {
            "method": "GET"
        }
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "device_id": "64768",
            "inode": "547127",
            "path": "/tmp/service_logs/test-gitlab-auth.log"
        },
        "offset": 0
    },
    "related": {
        "ip": [
            "67.43.156.18"
        ]
    },
    "source": {
        "address": "67.43.156.18",
        "as": {
            "number": 35908
        },
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.18"
    },
    "tags": [
        "preserve_original_event",
        "gitlab-auth"
    ],
    "url": {
        "path": "/group/project.git/info/refs",
        "query": "service=git-upload-pack"
    }
}
```

### pages

Collect logs for Pages. Check out the [GitLab Pages log docs](https://docs.gitlab.com/ee/administration/logs/#pages-logs) for more information.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| gitlab.pages.config_addr |  | keyword |
| gitlab.pages.content_type |  | keyword |
| gitlab.pages.correlation_id |  | keyword |
| gitlab.pages.duration_ms |  | long |
| gitlab.pages.error |  | keyword |
| gitlab.pages.gid |  | keyword |
| gitlab.pages.host |  | keyword |
| gitlab.pages.in_place |  | boolean |
| gitlab.pages.level |  | keyword |
| gitlab.pages.listen_addr.ip |  | ip |
| gitlab.pages.listen_addr.port |  | long |
| gitlab.pages.listen_addr.zone |  | keyword |
| gitlab.pages.lookup_name |  | keyword |
| gitlab.pages.method |  | keyword |
| gitlab.pages.msg |  | keyword |
| gitlab.pages.pages_https |  | boolean |
| gitlab.pages.proto |  | keyword |
| gitlab.pages.read_bytes |  | long |
| gitlab.pages.referrer |  | keyword |
| gitlab.pages.remote_addr |  | keyword |
| gitlab.pages.remote_ip |  | ip |
| gitlab.pages.revision |  | keyword |
| gitlab.pages.status |  | long |
| gitlab.pages.system |  | keyword |
| gitlab.pages.time |  | date |
| gitlab.pages.ttfb_ms |  | long |
| gitlab.pages.uid |  | keyword |
| gitlab.pages.uri |  | keyword |
| gitlab.pages.user_agent |  | keyword |
| gitlab.pages.version |  | keyword |
| gitlab.pages.written_bytes |  | long |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |


An example event for `pages` looks as following:

```json
{
    "@timestamp": "2020-04-22T17:53:12.000Z",
    "agent": {
        "ephemeral_id": "5362c9f9-3691-4e8e-9f46-17ea5b39b3c9",
        "id": "e62106e8-1ee2-44ac-a51a-02adcbe8e81a",
        "name": "elastic-agent-33649",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "gitlab.pages",
        "namespace": "43203",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e62106e8-1ee2-44ac-a51a-02adcbe8e81a",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "gitlab.pages",
        "ingested": "2026-03-30T07:14:27Z",
        "kind": "event",
        "level": 6,
        "original": "{\"level\": \"info\",\"msg\": \"GitLab Pages Daemon\",\"revision\": \"52b2899\",\"time\": \"2020-04-22T17:53:12Z\",\"version\": \"1.17.0\"}",
        "type": [
            "info"
        ]
    },
    "gitlab": {
        "pages": {
            "revision": "52b2899",
            "version": "1.17.0"
        }
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "elastic-agent-33649",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.241.2",
            "192.168.240.7"
        ],
        "mac": [
            "1E-FE-0D-E0-5F-C1",
            "46-0E-56-98-32-CB"
        ],
        "name": "elastic-agent-33649",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.15.0-173-generic",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "device_id": "64768",
            "inode": "547129",
            "path": "/tmp/service_logs/test-gitlab-pages.log"
        },
        "offset": 0
    },
    "message": "GitLab Pages Daemon",
    "tags": [
        "preserve_original_event",
        "gitlab-pages"
    ]
}
```

### production

Collect logs for Rails controller requests received from GitLab. Check out the [GitLab production log docs](https://docs.gitlab.com/ee/administration/logs/#production_jsonlog) for more information.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| gitlab.production.action |  | keyword |
| gitlab.production.controller |  | keyword |
| gitlab.production.correlation_id |  | keyword |
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
| gitlab.production.db_ci_replica_txn_max_duration_s |  | double |
| gitlab.production.db_ci_replica_wal_cached_count |  | long |
| gitlab.production.db_ci_replica_wal_count |  | long |
| gitlab.production.db_ci_replica_write_count |  | long |
| gitlab.production.db_ci_txn_count |  | long |
| gitlab.production.db_ci_txn_duration_s |  | float |
| gitlab.production.db_ci_txn_max_duration_s |  | double |
| gitlab.production.db_ci_wal_cached_count |  | long |
| gitlab.production.db_ci_wal_count |  | long |
| gitlab.production.db_ci_write_count |  | long |
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
| gitlab.production.db_main_replica_txn_max_duration_s |  | double |
| gitlab.production.db_main_replica_wal_cached_count |  | long |
| gitlab.production.db_main_replica_wal_count |  | long |
| gitlab.production.db_main_replica_write_count |  | long |
| gitlab.production.db_main_txn_count |  | long |
| gitlab.production.db_main_txn_duration_s |  | float |
| gitlab.production.db_main_txn_max_duration_s |  | double |
| gitlab.production.db_main_wal_cached_count |  | long |
| gitlab.production.db_main_wal_count |  | long |
| gitlab.production.db_main_write_count |  | long |
| gitlab.production.db_primary_cached_count |  | long |
| gitlab.production.db_primary_count |  | long |
| gitlab.production.db_primary_duration_s |  | float |
| gitlab.production.db_primary_txn_count |  | long |
| gitlab.production.db_primary_txn_duration_s |  | float |
| gitlab.production.db_primary_txn_max_duration_s |  | double |
| gitlab.production.db_primary_wal_cached_count |  | long |
| gitlab.production.db_primary_wal_count |  | long |
| gitlab.production.db_primary_write_count |  | long |
| gitlab.production.db_replica_cached_count |  | long |
| gitlab.production.db_replica_count |  | long |
| gitlab.production.db_replica_duration_s |  | float |
| gitlab.production.db_replica_txn_count |  | long |
| gitlab.production.db_replica_txn_duration_s |  | float |
| gitlab.production.db_replica_txn_max_duration_s |  | double |
| gitlab.production.db_replica_wal_cached_count |  | long |
| gitlab.production.db_replica_wal_count |  | long |
| gitlab.production.db_replica_write_count |  | long |
| gitlab.production.db_txn_count |  | long |
| gitlab.production.db_write_count |  | long |
| gitlab.production.duration_s | Total time to retrieve the request. | double |
| gitlab.production.exception.backtrace |  | text |
| gitlab.production.exception.class |  | keyword |
| gitlab.production.exception.message |  | text |
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
| gitlab.production.meta.organization_id |  | keyword |
| gitlab.production.meta.remote_ip |  | ip |
| gitlab.production.meta.search.page |  | keyword |
| gitlab.production.meta.user |  | keyword |
| gitlab.production.meta.user_id |  | long |
| gitlab.production.params.active |  | keyword |
| gitlab.production.params.assignee_username |  | keyword |
| gitlab.production.params.authenticity_token |  | keyword |
| gitlab.production.params.graphql.operationName |  | keyword |
| gitlab.production.params.graphql.query |  | keyword |
| gitlab.production.params.graphql.variables |  | keyword |
| gitlab.production.params.limit |  | keyword |
| gitlab.production.params.new_user.email |  | keyword |
| gitlab.production.params.new_user.first_name |  | keyword |
| gitlab.production.params.new_user.last_name |  | keyword |
| gitlab.production.params.new_user.password |  | keyword |
| gitlab.production.params.new_user.username |  | keyword |
| gitlab.production.params.offset |  | keyword |
| gitlab.production.params.operationName |  | keyword |
| gitlab.production.params.query |  | keyword |
| gitlab.production.params.search |  | keyword |
| gitlab.production.params.user.login |  | keyword |
| gitlab.production.params.user.password |  | keyword |
| gitlab.production.params.variables |  | keyword |
| gitlab.production.path |  | keyword |
| gitlab.production.path_traversal_check_duration_s |  | double |
| gitlab.production.pid | The worker’s Linux process ID. | keyword |
| gitlab.production.queue_duration_s |  | float |
| gitlab.production.rate_limiting_gates |  | keyword |
| gitlab.production.redis_allowed_cross_slot_calls |  | long |
| gitlab.production.redis_cache_calls |  | long |
| gitlab.production.redis_cache_duration_s |  | double |
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
| gitlab.production.ua |  | keyword |
| gitlab.production.view_duration_s |  | float |
| gitlab.production.worker_id |  | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |


An example event for `production` looks as following:

```json
{
    "@timestamp": "2024-04-03T20:44:09.068Z",
    "agent": {
        "ephemeral_id": "0f3e52a7-9952-4b9a-ae39-bbc6b56a6ae0",
        "id": "00918dce-39a5-43c0-9c69-e7dc1acb0fca",
        "name": "elastic-agent-12116",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "gitlab.production",
        "namespace": "77253",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "00918dce-39a5-43c0-9c69-e7dc1acb0fca",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "index",
        "agent_id_status": "verified",
        "dataset": "gitlab.production",
        "duration": 24200000,
        "id": "0bb7a10d-8da7-4499-8759-99ebe323f4b1",
        "ingested": "2026-03-30T07:16:47Z",
        "kind": "event",
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
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "elastic-agent-12116",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.241.2",
            "192.168.240.7"
        ],
        "mac": [
            "86-B8-23-AE-B7-40",
            "E6-15-09-BC-BA-B6"
        ],
        "name": "elastic-agent-12116",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.15.0-173-generic",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
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
            "device_id": "64768",
            "inode": "547129",
            "path": "/tmp/service_logs/test-gitlab-production.log"
        },
        "offset": 9793
    },
    "process": {
        "name": "puma_master",
        "pid": 857
    },
    "tags": [
        "preserve_original_event",
        "gitlab-production"
    ],
    "url": {
        "full": "http://example.org/users/sign_in",
        "path": "/"
    }
}
```

### sidekiq

Collect logs from sidekiq for jobs background jobs that take a long time. Check out the [GitLab sidekiq log docs](https://docs.gitlab.com/ee/administration/logs/#sidekiq-logs) for more information.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| gitlab.gitaly.calls |  | long |
| gitlab.gitaly.duration |  | long |
| gitlab.sidekiq.args |  | keyword |
| gitlab.sidekiq.class |  | keyword |
| gitlab.sidekiq.completed_at |  | date |
| gitlab.sidekiq.correlation_id |  | keyword |
| gitlab.sidekiq.cpu_s |  | double |
| gitlab.sidekiq.created_at |  | date |
| gitlab.sidekiq.database |  | keyword |
| gitlab.sidekiq.db.duration_m |  | double |
| gitlab.sidekiq.db.duration_s |  | double |
| gitlab.sidekiq.db_cached_count |  | long |
| gitlab.sidekiq.db_ci_cached_count |  | long |
| gitlab.sidekiq.db_ci_count |  | long |
| gitlab.sidekiq.db_ci_duration_s |  | double |
| gitlab.sidekiq.db_ci_replica_cached_count |  | long |
| gitlab.sidekiq.db_ci_replica_count |  | long |
| gitlab.sidekiq.db_ci_replica_duration_s |  | double |
| gitlab.sidekiq.db_ci_replica_txn_count |  | long |
| gitlab.sidekiq.db_ci_replica_txn_duration_s |  | double |
| gitlab.sidekiq.db_ci_replica_txn_max_duration_s |  | double |
| gitlab.sidekiq.db_ci_replica_wal_cached_count |  | long |
| gitlab.sidekiq.db_ci_replica_wal_count |  | long |
| gitlab.sidekiq.db_ci_replica_write_count |  | long |
| gitlab.sidekiq.db_ci_txn_count |  | long |
| gitlab.sidekiq.db_ci_txn_duration_s |  | double |
| gitlab.sidekiq.db_ci_txn_max_duration_s |  | double |
| gitlab.sidekiq.db_ci_wal_cached_count |  | long |
| gitlab.sidekiq.db_ci_wal_count |  | long |
| gitlab.sidekiq.db_ci_write_count |  | long |
| gitlab.sidekiq.db_count |  | long |
| gitlab.sidekiq.db_duration |  | double |
| gitlab.sidekiq.db_duration_s |  | double |
| gitlab.sidekiq.db_main_cached_count |  | long |
| gitlab.sidekiq.db_main_count |  | long |
| gitlab.sidekiq.db_main_duration_s |  | double |
| gitlab.sidekiq.db_main_replica_cached_count |  | long |
| gitlab.sidekiq.db_main_replica_count |  | long |
| gitlab.sidekiq.db_main_replica_duration_s |  | double |
| gitlab.sidekiq.db_main_replica_txn_count |  | long |
| gitlab.sidekiq.db_main_replica_txn_duration_s |  | double |
| gitlab.sidekiq.db_main_replica_txn_max_duration_s |  | double |
| gitlab.sidekiq.db_main_replica_wal_cached_count |  | long |
| gitlab.sidekiq.db_main_replica_wal_count |  | long |
| gitlab.sidekiq.db_main_replica_write_count |  | long |
| gitlab.sidekiq.db_main_txn_count |  | long |
| gitlab.sidekiq.db_main_txn_duration_s |  | double |
| gitlab.sidekiq.db_main_txn_max_duration_s |  | double |
| gitlab.sidekiq.db_main_wal_cached_count |  | long |
| gitlab.sidekiq.db_main_wal_count |  | long |
| gitlab.sidekiq.db_main_write_count |  | long |
| gitlab.sidekiq.db_primary_cached_count |  | long |
| gitlab.sidekiq.db_primary_count |  | long |
| gitlab.sidekiq.db_primary_duration_s |  | double |
| gitlab.sidekiq.db_primary_txn_count |  | long |
| gitlab.sidekiq.db_primary_txn_duration_s |  | double |
| gitlab.sidekiq.db_primary_txn_max_duration_s |  | double |
| gitlab.sidekiq.db_primary_wal_cached_count |  | long |
| gitlab.sidekiq.db_primary_wal_count |  | long |
| gitlab.sidekiq.db_primary_write_count |  | long |
| gitlab.sidekiq.db_replica_cached_count |  | long |
| gitlab.sidekiq.db_replica_count |  | long |
| gitlab.sidekiq.db_replica_duration_s |  | double |
| gitlab.sidekiq.db_replica_txn_count |  | long |
| gitlab.sidekiq.db_replica_txn_duration_s |  | double |
| gitlab.sidekiq.db_replica_txn_max_duration_s |  | double |
| gitlab.sidekiq.db_replica_wal_cached_count |  | long |
| gitlab.sidekiq.db_replica_wal_count |  | long |
| gitlab.sidekiq.db_replica_write_count |  | long |
| gitlab.sidekiq.db_txn_count |  | long |
| gitlab.sidekiq.db_write_count |  | long |
| gitlab.sidekiq.dead |  | boolean |
| gitlab.sidekiq.duration |  | double |
| gitlab.sidekiq.duration_s |  | double |
| gitlab.sidekiq.enqueue_latency_s |  | double |
| gitlab.sidekiq.enqueued_at |  | date |
| gitlab.sidekiq.exception.backtrace |  | text |
| gitlab.sidekiq.exception.class |  | keyword |
| gitlab.sidekiq.exception.message |  | text |
| gitlab.sidekiq.exclusive_lock_hold_duration_s |  | double |
| gitlab.sidekiq.exclusive_lock_requested_count |  | long |
| gitlab.sidekiq.exclusive_lock_wait_duration_s |  | double |
| gitlab.sidekiq.extra.batched_git_ref_updates_cleanup_scheduler_worker.stats.total_projects |  | long |
| gitlab.sidekiq.extra.cells_stale_requests_cleanup_cron_worker.removed_count |  | long |
| gitlab.sidekiq.extra.ci_catalog_resources_process_sync_events_worker.consumable_events |  | long |
| gitlab.sidekiq.extra.ci_catalog_resources_process_sync_events_worker.estimated_total_events |  | long |
| gitlab.sidekiq.extra.ci_pipeline_artifacts_expire_artifacts_worker.destroyed_pipeline_artifacts_count |  | long |
| gitlab.sidekiq.extra.ci_unlock_pipelines_in_queue_worker.remaining_pending |  | long |
| gitlab.sidekiq.extra.ci_update_locked_unknown_artifacts_worker.locked_count |  | long |
| gitlab.sidekiq.extra.ci_update_locked_unknown_artifacts_worker.removed_count |  | long |
| gitlab.sidekiq.extra.container_expiration_policy_worker.cleanup_required_count |  | long |
| gitlab.sidekiq.extra.container_expiration_policy_worker.cleanup_total_count |  | long |
| gitlab.sidekiq.extra.container_expiration_policy_worker.cleanup_unfinished_count |  | long |
| gitlab.sidekiq.extra.expire_build_artifacts_worker.destroyed_job_artifacts_count |  | long |
| gitlab.sidekiq.extra.loose_foreign_keys_ci_pipelines_builds_cleanup_cron_worker.stats.delete_count |  | long |
| gitlab.sidekiq.extra.loose_foreign_keys_ci_pipelines_builds_cleanup_cron_worker.stats.over_limit |  | boolean |
| gitlab.sidekiq.extra.loose_foreign_keys_ci_pipelines_builds_cleanup_cron_worker.stats.turbo_mode |  | boolean |
| gitlab.sidekiq.extra.loose_foreign_keys_ci_pipelines_builds_cleanup_cron_worker.stats.update_count |  | long |
| gitlab.sidekiq.extra.loose_foreign_keys_cleanup_worker.stats.connection |  | keyword |
| gitlab.sidekiq.extra.loose_foreign_keys_cleanup_worker.stats.delete_count |  | long |
| gitlab.sidekiq.extra.loose_foreign_keys_cleanup_worker.stats.over_limit |  | boolean |
| gitlab.sidekiq.extra.loose_foreign_keys_cleanup_worker.stats.turbo_mode |  | boolean |
| gitlab.sidekiq.extra.loose_foreign_keys_cleanup_worker.stats.update_count |  | long |
| gitlab.sidekiq.extra.loose_foreign_keys_merge_request_diff_commit_cleanup_worker.stats.delete_count |  | long |
| gitlab.sidekiq.extra.loose_foreign_keys_merge_request_diff_commit_cleanup_worker.stats.over_limit |  | boolean |
| gitlab.sidekiq.extra.loose_foreign_keys_merge_request_diff_commit_cleanup_worker.stats.turbo_mode |  | boolean |
| gitlab.sidekiq.extra.loose_foreign_keys_merge_request_diff_commit_cleanup_worker.stats.update_count |  | long |
| gitlab.sidekiq.extra.namespaces_process_sync_events_worker.consumable_events |  | long |
| gitlab.sidekiq.extra.namespaces_process_sync_events_worker.estimated_total_events |  | long |
| gitlab.sidekiq.extra.namespaces_process_sync_events_worker.processed_events |  | long |
| gitlab.sidekiq.extra.object_storage_delete_stale_direct_uploads_worker.execution_timeout |  | boolean |
| gitlab.sidekiq.extra.object_storage_delete_stale_direct_uploads_worker.total_deleted_stale_entries |  | long |
| gitlab.sidekiq.extra.object_storage_delete_stale_direct_uploads_worker.total_pending_entries |  | long |
| gitlab.sidekiq.extra.packages_cleanup_delete_orphaned_dependencies_worker.deleted_rows_count |  | long |
| gitlab.sidekiq.extra.packages_cleanup_delete_orphaned_dependencies_worker.last_processed_packages_dependency_id |  | long |
| gitlab.sidekiq.extra.pages_deactivate_expired_deployments_cron_worker.deactivate_expired_pages_deployments.deactivated_deployments |  | long |
| gitlab.sidekiq.extra.pages_deactivate_expired_deployments_cron_worker.deactivate_expired_pages_deployments.duration |  | double |
| gitlab.sidekiq.extra.projects_process_sync_events_worker.consumable_events |  | long |
| gitlab.sidekiq.extra.projects_process_sync_events_worker.estimated_total_events |  | long |
| gitlab.sidekiq.extra.projects_process_sync_events_worker.processed_events |  | long |
| gitlab.sidekiq.gitaly_calls |  | long |
| gitlab.sidekiq.gitaly_duration |  | long |
| gitlab.sidekiq.idempotency_key |  | keyword |
| gitlab.sidekiq.jid |  | keyword |
| gitlab.sidekiq.job_size_bytes |  | long |
| gitlab.sidekiq.job_status |  | keyword |
| gitlab.sidekiq.load_balancing_strategy |  | keyword |
| gitlab.sidekiq.mem_bytes |  | long |
| gitlab.sidekiq.mem_mallocs |  | long |
| gitlab.sidekiq.mem_objects |  | long |
| gitlab.sidekiq.mem_total_bytes |  | long |
| gitlab.sidekiq.message |  | keyword |
| gitlab.sidekiq.meta.caller_id |  | keyword |
| gitlab.sidekiq.meta.client_id |  | keyword |
| gitlab.sidekiq.meta.feature_category |  | keyword |
| gitlab.sidekiq.meta.gl_user_id |  | keyword |
| gitlab.sidekiq.meta.organization_id |  | keyword |
| gitlab.sidekiq.meta.project |  | keyword |
| gitlab.sidekiq.meta.remote_ip |  | ip |
| gitlab.sidekiq.meta.root_caller_id |  | keyword |
| gitlab.sidekiq.meta.root_namespace |  | keyword |
| gitlab.sidekiq.meta.user |  | keyword |
| gitlab.sidekiq.pid |  | long |
| gitlab.sidekiq.queue |  | keyword |
| gitlab.sidekiq.queue_duration_s |  | double |
| gitlab.sidekiq.queue_namespace |  | keyword |
| gitlab.sidekiq.redis_cache_calls |  | long |
| gitlab.sidekiq.redis_cache_duration_s |  | double |
| gitlab.sidekiq.redis_cache_read_bytes |  | long |
| gitlab.sidekiq.redis_cache_write_bytes |  | long |
| gitlab.sidekiq.redis_calls | Total number of calls made to Redis. | long |
| gitlab.sidekiq.redis_duration_s |  | double |
| gitlab.sidekiq.redis_feature_flag_calls |  | long |
| gitlab.sidekiq.redis_feature_flag_duration_s |  | double |
| gitlab.sidekiq.redis_feature_flag_read_bytes |  | long |
| gitlab.sidekiq.redis_feature_flag_write_bytes |  | long |
| gitlab.sidekiq.redis_queues_calls |  | long |
| gitlab.sidekiq.redis_queues_duration_s |  | double |
| gitlab.sidekiq.redis_queues_metadata_calls |  | long |
| gitlab.sidekiq.redis_queues_metadata_duration_s |  | double |
| gitlab.sidekiq.redis_queues_metadata_read_bytes |  | long |
| gitlab.sidekiq.redis_queues_metadata_write_bytes |  | long |
| gitlab.sidekiq.redis_queues_read_bytes |  | long |
| gitlab.sidekiq.redis_queues_write_bytes |  | long |
| gitlab.sidekiq.redis_rate_limiting_calls |  | long |
| gitlab.sidekiq.redis_rate_limiting_duration_s |  | double |
| gitlab.sidekiq.redis_rate_limiting_read_bytes |  | long |
| gitlab.sidekiq.redis_rate_limiting_write_bytes |  | long |
| gitlab.sidekiq.redis_read_bytes |  | long |
| gitlab.sidekiq.redis_shared_state_calls |  | long |
| gitlab.sidekiq.redis_shared_state_duration_s |  | double |
| gitlab.sidekiq.redis_shared_state_read_bytes |  | long |
| gitlab.sidekiq.redis_shared_state_write_bytes |  | long |
| gitlab.sidekiq.redis_write_bytes |  | long |
| gitlab.sidekiq.retried_at |  | date |
| gitlab.sidekiq.retry |  | boolean |
| gitlab.sidekiq.retry_count |  | long |
| gitlab.sidekiq.retry_long |  | long |
| gitlab.sidekiq.scheduled_at |  | date |
| gitlab.sidekiq.scheduler |  | keyword |
| gitlab.sidekiq.scheduling_latency_s |  | double |
| gitlab.sidekiq.sidekiq_thread_name |  | keyword |
| gitlab.sidekiq.sidekiq_tid |  | keyword |
| gitlab.sidekiq.size_limiter |  | keyword |
| gitlab.sidekiq.size_limiter_computed_size_bytes |  | long |
| gitlab.sidekiq.size_limiter_limit_bytes |  | long |
| gitlab.sidekiq.size_limiter_limiter |  | keyword |
| gitlab.sidekiq.size_limiter_safe_bytes |  | long |
| gitlab.sidekiq.status |  | keyword |
| gitlab.sidekiq.status_expiration |  | long |
| gitlab.sidekiq.store |  | keyword |
| gitlab.sidekiq.target_duration_s |  | long |
| gitlab.sidekiq.target_scheduling_latency_s |  | long |
| gitlab.sidekiq.time |  | date |
| gitlab.sidekiq.trace_propagation_headers.baggage |  | keyword |
| gitlab.sidekiq.trace_propagation_headers.sentry_trace |  | keyword |
| gitlab.sidekiq.unique_args |  | keyword |
| gitlab.sidekiq.unique_digest |  | keyword |
| gitlab.sidekiq.unique_expiration |  | long |
| gitlab.sidekiq.unique_strategy |  | keyword |
| gitlab.sidekiq.urgency |  | keyword |
| gitlab.sidekiq.version |  | long |
| gitlab.sidekiq.wal_location_sources.ci |  | keyword |
| gitlab.sidekiq.wal_location_sources.main |  | keyword |
| gitlab.sidekiq.worker_data_consistency |  | keyword |
| gitlab.sidekiq.worker_data_consistency_per_db.ci |  | keyword |
| gitlab.sidekiq.worker_data_consistency_per_db.main |  | keyword |
| gitlab.sidekiq.worker_id |  | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |


An example event for `sidekiq` looks as following:

```json
{
    "@timestamp": "2018-04-03T22:57:22.071Z",
    "agent": {
        "ephemeral_id": "96d55f2a-0c1b-472e-bf08-c056fadccf39",
        "id": "6222b3fc-41bf-44c8-964a-bd0a376033ba",
        "name": "elastic-agent-88111",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "gitlab.sidekiq",
        "namespace": "11880",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "6222b3fc-41bf-44c8-964a-bd0a376033ba",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "gitlab.sidekiq",
        "duration": 139000000,
        "end": "2018-04-03T22:57:22.071Z",
        "ingested": "2026-03-30T07:35:08Z",
        "kind": "event",
        "original": "{\"severity\": \"INFO\",\"time\": \"2018-04-03T22:57:22.071Z\",\"queue\": \"cronjob:update_all_mirrors\",\"args\": [],\"class\": \"UpdateAllMirrorsWorker\",\"retry\": false,\"queue_namespace\": \"cronjob\",\"jid\": \"06aeaa3b0aadacf9981f368e\",\"created_at\": \"2018-04-03T22:57:21.930Z\",\"enqueued_at\": \"2018-04-03T22:57:21.931Z\",\"pid\": 10077,\"worker_id\": \"sidekiq_0\",\"message\": \"UpdateAllMirrorsWorker JID-06aeaa3b0aadacf9981f368e: done: 0.139 sec\",\"job_status\": \"done\",\"duration\": 0.139,\"completed_at\": \"2018-04-03T22:57:22.071Z\",\"db_duration\": 0.05,\"db_duration_s\": 0.0005,\"gitaly_duration\": 0,\"gitaly_calls\": 0}",
        "severity": 6,
        "start": "2018-04-03T22:57:21.930Z",
        "type": [
            "info"
        ]
    },
    "gitlab": {
        "gitaly": {
            "calls": 0,
            "duration": 0
        },
        "sidekiq": {
            "class": "UpdateAllMirrorsWorker",
            "db": {
                "duration_m": 0.05,
                "duration_s": 0.0005
            },
            "enqueued_at": "2018-04-03T22:57:21.931Z",
            "jid": "06aeaa3b0aadacf9981f368e",
            "job_status": "done",
            "queue": "cronjob:update_all_mirrors",
            "queue_namespace": "cronjob",
            "retry": false,
            "worker_id": "sidekiq_0"
        }
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "elastic-agent-88111",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.241.2",
            "192.168.240.7"
        ],
        "mac": [
            "2A-6B-40-0B-16-64",
            "D2-6B-78-02-AE-8F"
        ],
        "name": "elastic-agent-88111",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.15.0-173-generic",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "device_id": "64768",
            "inode": "547165",
            "path": "/tmp/service_logs/test-gitlab-sidekiq.log"
        },
        "offset": 0
    },
    "message": "UpdateAllMirrorsWorker JID-06aeaa3b0aadacf9981f368e: done: 0.139 sec",
    "process": {
        "pid": 10077
    },
    "tags": [
        "preserve_original_event",
        "gitlab-sidekiq"
    ]
}
```
