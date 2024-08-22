# GitLab Integration

This integration is for ingesting logs from [GitLab](https://about.gitlab.com/).

- `api`: Collect logs for HTTP requests made to the GitLab API

- `application`: Collect logs for events in GitLab like user creation or project deletion.

- `audit`: Collect logs for changes to group or project settings and memberships.

- `auth`: Collect logs for protected paths abusive requests or requests over the Rate Limit.

- `production`: Collect logs for Rails controller requests received from GitLab.

See the GitLab [Log system docs](https://docs.gitlab.com/ee/administration/logs/) for more information.

## Compatibility

The GitLab module has been developed with and tested against the [community edition](https://gitlab.com/rluna-gitlab/gitlab-ce) version 16.8.5-ce.0. 

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
| gitlab.application.current_iteration |  | long |
| gitlab.application.event |  | keyword |
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
| gitlab.application.partition_name |  | keyword |
| gitlab.application.project_id |  | long |
| gitlab.application.project_name |  | keyword |
| gitlab.application.shared_connection_name |  | keyword |
| gitlab.application.silent_mode_enabled |  | boolean |
| gitlab.application.table_name |  | keyword |
| gitlab.application.user_admin |  | boolean |
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
| log.file.inode | Inode number of the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Log offset | long |


An example event for `application` looks as following:

```json
{
    "@timestamp": "2024-05-10T17:49:45.825Z",
    "agent": {
        "ephemeral_id": "c6d67ec9-17b1-4f21-851f-01582fac9c04",
        "id": "e6f355cf-f8da-4049-b560-1a42e0dc21c5",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.1"
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
        "namespace": "47114",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e6f355cf-f8da-4049-b560-1a42e0dc21c5",
        "snapshot": false,
        "version": "8.14.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "dataset": "gitlab.application",
        "id": "01HXHSYJJQNY08JV4JF2B69ZDR",
        "ingested": "2024-08-05T14:13:26Z",
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
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "device_id": "30",
            "inode": "224",
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
        "gitlab-application",
        "forwarded"
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
| log.file.inode | Inode number of the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Log offset | long |


An example event for `audit` looks as following:

```json
{
    "@timestamp": "2018-10-17T17:38:22.523Z",
    "agent": {
        "ephemeral_id": "88cea3d2-b910-479c-9a11-035ae92ed5c0",
        "id": "e6f355cf-f8da-4049-b560-1a42e0dc21c5",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.1"
    },
    "data_stream": {
        "dataset": "gitlab.audit",
        "namespace": "33114",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e6f355cf-f8da-4049-b560-1a42e0dc21c5",
        "snapshot": false,
        "version": "8.14.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "gitlab.audit",
        "ingested": "2024-08-05T14:18:18Z",
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
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "device_id": "30",
            "inode": "235",
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
        "gitlab-audit",
        "forwarded"
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
| gitlab.auth.redis_cache_duration_s |  | float |
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
| log.file.inode | Inode number of the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Log offset | long |


An example event for `auth` looks as following:

```json
{
    "@timestamp": "2023-04-19T22:14:25.893Z",
    "agent": {
        "ephemeral_id": "8a41758c-b013-476c-b333-58bb2ce2be7c",
        "id": "e6f355cf-f8da-4049-b560-1a42e0dc21c5",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.1"
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
        "namespace": "58237",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e6f355cf-f8da-4049-b560-1a42e0dc21c5",
        "snapshot": false,
        "version": "8.14.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "gitlab.auth",
        "id": "01GYDSAKAN2SPZPAMJNRWW5H8S",
        "ingested": "2024-08-05T14:23:51Z",
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
            "device_id": "30",
            "inode": "251",
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
        "gitlab-auth",
        "forwarded"
    ],
    "url": {
        "path": "/group/project.git/info/refs",
        "query": "service=git-upload-pack"
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
