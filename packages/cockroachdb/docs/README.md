# CockroachDB Integration

This integration collects metrics from CockroachDB. It includes the
following datasets for receiving logs:

- `status` datastream: consists of status metrics

## Compatibility

The CockroachDB integration is compatible with any CockroachDB version
exposing metrics in Prometheus format.

### status

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
| cockroachdb.status.\*.counter | Prometheus counter metric | object |
| cockroachdb.status.\*.histogram | Prometheus histogram metric | object |
| cockroachdb.status.\*.rate | Prometheus rated counter metric | object |
| cockroachdb.status.\*.value | Prometheus gauge metric | object |
| cockroachdb.status.labels.\* | Prometheus metric labels | object |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host | A host is defined as a general computing instance. ECS host.\* fields should be populated with details about the host on which the event happened, or from which the measurement was taken. Host types include hardware, virtual machines, Docker containers, and Kubernetes nodes. | group |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
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
| service.address | Service address | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


An example event for `status` looks as following:

```json
{
    "cockroachdb": {
        "status": {
            "raft_rcvd_prevote": {
                "counter": 0
            },
            "rocksdb_bloom_filter_prefix_useful": {
                "value": 0
            },
            "keycount": {
                "value": 0
            },
            "queue_gc_info_resolvefailed": {
                "counter": 0
            },
            "queue_gc_info_resolvetotal": {
                "counter": 0
            },
            "raft_process_tickingnanos": {
                "counter": 0
            },
            "raft_rcvd_dropped": {
                "counter": 0
            },
            "tscache_skl_rotations": {
                "counter": 0
            },
            "txnwaitqueue_pusher_waiting": {
                "value": 0
            },
            "queue_merge_processingnanos": {
                "counter": 0
            },
            "queue_gc_info_transactionspangccommitted": {
                "counter": 0
            },
            "queue_gc_info_intenttxns": {
                "counter": 0
            },
            "queue_raftsnapshot_process_success": {
                "counter": 0
            },
            "range_snapshots_applied_non_voter": {
                "counter": 0
            },
            "rebalancing_range_rebalances": {
                "counter": 0
            },
            "follower_reads_success_count": {
                "counter": 0
            },
            "abortspanbytes": {
                "value": 0
            },
            "queue_tsmaintenance_processingnanos": {
                "counter": 0
            },
            "rocksdb_bloom_filter_prefix_checked": {
                "value": 0
            },
            "labels": {
                "instance": "host.docker.internal:8082",
                "store": "2",
                "job": "cockroachdb"
            },
            "raft_enqueued_pending": {
                "value": 0
            },
            "rebalancing_writespersecond": {
                "value": 0
            },
            "queue_tsmaintenance_process_success": {
                "counter": 0
            },
            "rocksdb_block_cache_misses": {
                "value": 12
            },
            "raft_rcvd_snap": {
                "counter": 0
            },
            "queue_merge_process_success": {
                "counter": 0
            },
            "raft_entrycache_accesses": {
                "counter": 0
            },
            "kv_closed_timestamp_failures_to_close": {
                "value": 0
            },
            "replicas_leaders": {
                "value": 0
            },
            "queue_split_pending": {
                "value": 0
            },
            "queue_raftsnapshot_processingnanos": {
                "counter": 0
            },
            "ranges_overreplicated": {
                "value": 0
            },
            "leases_transfers_error": {
                "counter": 0
            },
            "rebalancing_queriespersecond": {
                "value": 0
            },
            "queue_gc_info_numkeysaffected": {
                "counter": 0
            },
            "raft_rcvd_prop": {
                "counter": 0
            },
            "queue_replicagc_pending": {
                "value": 0
            },
            "rebalancing_lease_transfers": {
                "counter": 0
            },
            "queue_replicate_process_success": {
                "counter": 0
            },
            "leases_success": {
                "counter": 0
            },
            "raftlog_truncated": {
                "counter": 0
            },
            "queue_replicate_addreplica": {
                "counter": 0
            },
            "storage_disk_stalled": {
                "value": 0
            },
            "queue_raftlog_process_failure": {
                "counter": 0
            },
            "rocksdb_memtable_total_size": {
                "value": 1310720.0
            },
            "queue_replicagc_process_failure": {
                "counter": 0
            },
            "raft_rcvd_timeoutnow": {
                "counter": 0
            },
            "range_removes": {
                "counter": 0
            },
            "queue_merge_pending": {
                "value": 0
            },
            "raft_rcvd_appresp": {
                "counter": 0
            },
            "range_adds": {
                "counter": 0
            },
            "queue_replicate_processingnanos": {
                "counter": 0
            },
            "addsstable_delay_enginebackpressure": {
                "counter": 0
            },
            "valcount": {
                "value": 0
            },
            "rocksdb_block_cache_pinned_usage": {
                "value": 0
            },
            "queue_replicate_pending": {
                "value": 0
            },
            "queue_consistency_pending": {
                "value": 0
            },
            "raft_entrycache_size": {
                "value": 0
            },
            "queue_tsmaintenance_pending": {
                "value": 0
            },
            "requests_slow_raft": {
                "value": 0
            },
            "addsstable_copies": {
                "counter": 0
            },
            "addsstable_proposals": {
                "counter": 0
            },
            "rocksdb_block_cache_usage": {
                "value": 1264
            },
            "queue_gc_info_transactionspangcaborted": {
                "counter": 0
            },
            "raft_entrycache_bytes": {
                "value": 0
            },
            "txnwaitqueue_pushee_waiting": {
                "value": 0
            },
            "livebytes": {
                "value": 0
            },
            "txnrecovery_failures": {
                "counter": 0
            },
            "syscount": {
                "value": 0
            },
            "rocksdb_num_sstables": {
                "value": 1
            },
            "leases_epoch": {
                "value": 0
            },
            "queue_split_purgatory": {
                "value": 0
            },
            "ranges": {
                "value": 0
            },
            "txnrecovery_attempts_total": {
                "counter": 0
            },
            "queue_merge_purgatory": {
                "value": 0
            },
            "queue_gc_info_transactionspangcstaging": {
                "counter": 0
            },
            "queue_gc_info_resolvesuccess": {
                "counter": 0
            },
            "kv_tenant_rate_limit_write_bytes_admitted": {
                "counter": 0
            },
            "queue_tsmaintenance_process_failure": {
                "counter": 0
            },
            "capacity_used": {
                "value": 1.0439201E7
            },
            "txnrecovery_attempts_pending": {
                "value": 0
            },
            "queue_merge_process_failure": {
                "counter": 0
            },
            "rocksdb_flushed_bytes": {
                "value": 0
            },
            "addsstable_delay_total": {
                "counter": 0
            },
            "txnrecovery_successes_aborted": {
                "counter": 0
            },
            "raft_rcvd_voteresp": {
                "counter": 0
            },
            "capacity_available": {
                "value": 5.37076989952E11
            },
            "raft_rcvd_vote": {
                "counter": 0
            },
            "range_snapshots_applied_voter": {
                "counter": 0
            },
            "txnrecovery_successes_committed": {
                "counter": 0
            },
            "requests_slow_lease": {
                "value": 0
            },
            "replicas": {
                "value": 0
            },
            "rocksdb_estimated_pending_compaction": {
                "value": 0
            },
            "raftlog_behind": {
                "value": 0
            },
            "storage_disk_slow": {
                "value": 0
            },
            "raft_commandsapplied": {
                "counter": 0
            },
            "queue_gc_info_transactionspangcpending": {
                "counter": 0
            },
            "requests_backpressure_split": {
                "value": 0
            },
            "requests_slow_latch": {
                "value": 0
            },
            "kv_tenant_rate_limit_current_blocked": {
                "value": 0
            },
            "kv_tenant_rate_limit_read_bytes_admitted": {
                "counter": 0
            },
            "rocksdb_block_cache_hits": {
                "value": 21
            },
            "rocksdb_compacted_bytes_read": {
                "value": 2583
            },
            "txnrecovery_successes_pending": {
                "counter": 0
            },
            "queue_raftsnapshot_process_failure": {
                "counter": 0
            },
            "rocksdb_table_readers_mem_estimate": {
                "value": 616
            },
            "queue_replicate_purgatory": {
                "value": 0
            },
            "valbytes": {
                "value": 0
            },
            "intentage": {
                "value": 0
            },
            "queue_replicate_removedeadreplica": {
                "counter": 0
            },
            "gcbytesage": {
                "value": 0
            },
            "queue_replicagc_processingnanos": {
                "counter": 0
            },
            "queue_replicate_process_failure": {
                "counter": 0
            },
            "leases_expiration": {
                "value": 0
            },
            "rocksdb_compactions": {
                "value": 1
            },
            "queue_replicate_removelearnerreplica": {
                "counter": 0
            },
            "raft_heartbeats_pending": {
                "value": 0
            },
            "leases_error": {
                "counter": 0
            },
            "queue_gc_info_transactionresolvefailed": {
                "counter": 0
            },
            "intentcount": {
                "value": 0
            },
            "capacity": {
                "value": 1.004205502464E12
            },
            "queue_raftlog_process_success": {
                "counter": 0
            },
            "leases_transfers_success": {
                "counter": 0
            },
            "intents_poison_attempts": {
                "counter": 0
            },
            "queue_replicate_removereplica": {
                "counter": 0
            },
            "range_splits": {
                "counter": 0
            },
            "intents_resolve_attempts": {
                "counter": 0
            },
            "replicas_quiescent": {
                "value": 0
            },
            "queue_raftlog_processingnanos": {
                "counter": 0
            },
            "txnwaitqueue_pusher_slow": {
                "value": 0
            },
            "raft_rcvd_transferleader": {
                "counter": 0
            },
            "keybytes": {
                "value": 0
            },
            "kv_tenant_rate_limit_read_requests_admitted": {
                "counter": 0
            },
            "rocksdb_ingested_bytes": {
                "value": 0
            },
            "range_snapshots_generated": {
                "counter": 0
            },
            "rocksdb_compacted_bytes_written": {
                "value": 1210
            },
            "sysbytes": {
                "value": 0
            },
            "queue_gc_info_pushtxn": {
                "counter": 0
            },
            "capacity_reserved": {
                "value": 0
            },
            "raft_rcvd_heartbeatresp": {
                "counter": 0
            },
            "intentresolver_async_throttled": {
                "counter": 0
            },
            "range_raftleadertransfers": {
                "counter": 0
            },
            "queue_gc_info_abortspanscanned": {
                "counter": 0
            },
            "replicas_reserved": {
                "value": 0
            },
            "queue_gc_info_transactionspanscanned": {
                "counter": 0
            },
            "ranges_unavailable": {
                "value": 0
            },
            "txnwaitqueue_query_waiting": {
                "value": 0
            },
            "replicas_leaders_not_leaseholders": {
                "value": 0
            },
            "queue_replicate_transferlease": {
                "counter": 0
            },
            "queue_split_process_success": {
                "counter": 0
            },
            "totalbytes": {
                "value": 0
            },
            "queue_split_process_failure": {
                "counter": 0
            },
            "intents_abort_attempts": {
                "counter": 0
            },
            "raft_rcvd_app": {
                "counter": 0
            },
            "intents_resolve_conflicting_rejected": {
                "counter": 0
            },
            "kv_rangefeed_catchup_scan_nanos": {
                "counter": 0
            },
            "kv_closed_timestamp_max_behind_nanos": {
                "value": 0
            },
            "addsstable_applications": {
                "counter": 0
            },
            "queue_replicagc_removereplica": {
                "counter": 0
            },
            "queue_consistency_process_success": {
                "counter": 0
            },
            "rocksdb_read_amplification": {
                "value": 1
            },
            "queue_replicate_voterdemotions": {
                "counter": 0
            },
            "range_merges": {
                "counter": 0
            },
            "replicas_leaseholders": {
                "value": 0
            },
            "kv_tenant_rate_limit_num_tenants": {
                "value": 0
            },
            "queue_gc_process_success": {
                "counter": 0
            },
            "rocksdb_encryption_algorithm": {
                "value": 0
            },
            "range_snapshots_applied_initial": {
                "counter": 0
            },
            "queue_raftlog_pending": {
                "value": 0
            },
            "ranges_underreplicated": {
                "value": 0
            },
            "raft_rcvd_heartbeat": {
                "counter": 0
            },
            "queue_replicagc_process_success": {
                "counter": 0
            },
            "queue_replicate_rebalancereplica": {
                "counter": 0
            },
            "raft_ticks": {
                "counter": 79959
            },
            "queue_consistency_process_failure": {
                "counter": 0
            },
            "queue_gc_processingnanos": {
                "counter": 0
            },
            "rocksdb_flushes": {
                "value": 0
            },
            "queue_gc_info_intentsconsidered": {
                "counter": 0
            },
            "queue_gc_info_abortspanconsidered": {
                "counter": 0
            },
            "txnwaitqueue_deadlocks_total": {
                "counter": 0
            },
            "intents_finalized_txns_timed_out": {
                "counter": 0
            },
            "queue_gc_pending": {
                "value": 0
            },
            "raft_process_workingnanos": {
                "counter": 0
            },
            "raft_entrycache_hits": {
                "counter": 0
            },
            "raft_rcvd_prevoteresp": {
                "counter": 0
            },
            "queue_split_processingnanos": {
                "counter": 0
            },
            "kv_tenant_rate_limit_write_requests_admitted": {
                "counter": 0
            },
            "queue_gc_info_abortspangcnum": {
                "counter": 0
            },
            "queue_replicate_nonvoterpromotions": {
                "counter": 0
            },
            "tscache_skl_pages": {
                "value": 1
            },
            "queue_gc_process_failure": {
                "counter": 0
            },
            "queue_raftsnapshot_pending": {
                "value": 0
            },
            "livecount": {
                "value": 0
            },
            "intentresolver_finalized_txns_failed": {
                "counter": 0
            },
            "txn_commit_waits_before_commit_trigger": {
                "counter": 0
            },
            "intentbytes": {
                "value": 0
            },
            "queue_consistency_processingnanos": {
                "counter": 0
            }
        }
    },
    "agent": {
        "hostname": "docker-fleet-agent",
        "name": "docker-fleet-agent",
        "id": "f81e793d-14ff-4995-9e2a-df5401a0def6",
        "type": "metricbeat",
        "ephemeral_id": "c4046388-5b3c-4a5e-8329-081bacffcda7",
        "version": "7.15.0"
    },
    "elastic_agent": {
        "id": "f81e793d-14ff-4995-9e2a-df5401a0def6",
        "version": "7.15.0",
        "snapshot": true
    },
    "@timestamp": "2021-10-06T09:24:38.976Z",
    "ecs": {
        "version": "1.11.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "cockroachdb.status"
    },
    "service": {
        "address": "http://host.docker.internal:8082/_status/vars",
        "type": "cockroachdb"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "4.19.128-microsoft-standard",
            "codename": "Core",
            "name": "CentOS Linux",
            "type": "linux",
            "family": "redhat",
            "version": "7 (Core)",
            "platform": "centos"
        },
        "containerized": true,
        "ip": [
            "172.24.0.7"
        ],
        "name": "docker-fleet-agent",
        "id": "6505f7ca36739e7eb909bdb52bf3ec18",
        "mac": [
            "02:42:ac:18:00:07"
        ],
        "architecture": "x86_64"
    },
    "metricset": {
        "period": 10000,
        "name": "status"
    },
    "event": {
        "duration": 22405300,
        "agent_id_status": "verified",
        "ingested": "2021-10-06T09:24:40Z",
        "module": "cockroachdb",
        "dataset": "cockroachdb.status"
    }
}
```


