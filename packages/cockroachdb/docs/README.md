# CockroachDB Integration

This integration collects metrics from [CockroachDB](https://www.cockroachlabs.com/docs/stable/developer-guide-overview.html). It includes the following datasets for receiving logs:

- `status` datastream: consists of status metrics

## Compatibility

The CockroachDB integration is compatible with any CockroachDB version
exposing metrics in Prometheus format.

### status

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id |  | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| cockroachdb.status.\*.counter | Prometheus counter metric | object | counter |
| cockroachdb.status.\*.histogram | Prometheus histogram metric | object |  |
| cockroachdb.status.\*.rate | Prometheus rated counter metric | object | counter |
| cockroachdb.status.\*.value | Prometheus gauge metric | object | gauge |
| cockroachdb.status.labels.advertise_addr | The IP address/hostname and port to tell other nodes to use. | keyword |  |
| cockroachdb.status.labels.go_version | The version of Go in which the source code is written. | keyword |  |
| cockroachdb.status.labels.http_addr | The IP address/hostname and port to listen on for DB Console HTTP requests. | keyword |  |
| cockroachdb.status.labels.instance | The \<host\>:\<port\> part of the cockroachdb URL/endpoint that is scraped. | keyword |  |
| cockroachdb.status.labels.job | The configured job name that the cockroachdb belongs to. | keyword |  |
| cockroachdb.status.labels.sql_addr | The IP address/hostname and port to listen on for SQL connections from clients. | keyword |  |
| cockroachdb.status.labels.store | Each CockroachDB node contains at least one store, which is where the cockroach process reads and writes its data on disk. | keyword |  |
| cockroachdb.status.labels.tag | The CockroachDB version. | keyword |  |
| cockroachdb.status.up.value | 1 if the instance is healthy, i.e. reachable, or 0 if the scrape failed. | keyword |  |
| cockroachdb.status.up.value_description | up if the instance is healthy, i.e. reachable, or down if the scrape failed. | keyword |  |
| container.id | Unique container id. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host | A host is defined as a general computing instance. ECS host.\* fields should be populated with details about the host on which the event happened, or from which the measurement was taken. Host types include hardware, virtual machines, Docker containers, and Kubernetes nodes. | group |  |
| host.containerized | If the host is a container. | boolean |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| service.address | Service address | keyword |  |


An example event for `status` looks as following:

```json
{
    "@timestamp": "2022-09-06T09:50:54.422Z",
    "agent": {
        "ephemeral_id": "4002fdcf-5421-491e-90b0-4b0229592d88",
        "id": "19de6249-945f-46da-9464-383664c3adaf",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.4.0"
    },
    "cockroachdb": {
        "status": {
            "abortspanbytes": {
                "value": 0
            },
            "addsstable_applications": {
                "counter": 0
            },
            "addsstable_aswrites": {
                "counter": 0
            },
            "addsstable_copies": {
                "counter": 0
            },
            "addsstable_delay_enginebackpressure": {
                "counter": 0
            },
            "addsstable_delay_total": {
                "counter": 0
            },
            "addsstable_proposals": {
                "counter": 0
            },
            "capacity": {
                "value": 0
            },
            "capacity_available": {
                "value": 0
            },
            "capacity_reserved": {
                "value": 0
            },
            "capacity_used": {
                "value": 0
            },
            "exportrequest_delay_total": {
                "counter": 0
            },
            "follower_reads_success_count": {
                "counter": 0
            },
            "gcbytesage": {
                "value": 0
            },
            "intentage": {
                "value": 0
            },
            "intentbytes": {
                "value": 0
            },
            "intentcount": {
                "value": 0
            },
            "intentresolver_async_throttled": {
                "counter": 0
            },
            "intentresolver_finalized_txns_failed": {
                "counter": 0
            },
            "intentresolver_intents_failed": {
                "counter": 0
            },
            "intents_abort_attempts": {
                "counter": 0
            },
            "intents_poison_attempts": {
                "counter": 0
            },
            "intents_resolve_attempts": {
                "counter": 54
            },
            "keybytes": {
                "value": 82632
            },
            "keycount": {
                "value": 1680
            },
            "kv_allocator_load_based_lease_transfers_cannot_find_better_candidate": {
                "counter": 0
            },
            "kv_allocator_load_based_lease_transfers_delta_not_significant": {
                "counter": 0
            },
            "kv_allocator_load_based_lease_transfers_existing_not_overfull": {
                "counter": 0
            },
            "kv_allocator_load_based_lease_transfers_missing_stats_for_existing_stores": {
                "counter": 0
            },
            "kv_allocator_load_based_lease_transfers_should_transfer": {
                "counter": 0
            },
            "kv_allocator_load_based_lease_transfers_significantly_switches_relative_disposition": {
                "counter": 0
            },
            "kv_allocator_load_based_replica_rebalancing_cannot_find_better_candidate": {
                "counter": 0
            },
            "kv_allocator_load_based_replica_rebalancing_delta_not_significant": {
                "counter": 0
            },
            "kv_allocator_load_based_replica_rebalancing_existing_not_overfull": {
                "counter": 0
            },
            "kv_allocator_load_based_replica_rebalancing_missing_stats_for_existing_store": {
                "counter": 0
            },
            "kv_allocator_load_based_replica_rebalancing_should_transfer": {
                "counter": 0
            },
            "kv_allocator_load_based_replica_rebalancing_significantly_switches_relative_disposition": {
                "counter": 0
            },
            "kv_closed_timestamp_max_behind_nanos": {
                "value": 0
            },
            "kv_concurrency_avg_lock_hold_duration_nanos": {
                "value": 0
            },
            "kv_concurrency_avg_lock_wait_duration_nanos": {
                "value": 0
            },
            "kv_concurrency_lock_wait_queue_waiters": {
                "value": 0
            },
            "kv_concurrency_locks": {
                "value": 0
            },
            "kv_concurrency_locks_with_wait_queues": {
                "value": 0
            },
            "kv_concurrency_max_lock_hold_duration_nanos": {
                "value": 0
            },
            "kv_concurrency_max_lock_wait_duration_nanos": {
                "value": 0
            },
            "kv_concurrency_max_lock_wait_queue_waiters_for_lock": {
                "value": 0
            },
            "kv_rangefeed_budget_allocation_blocked": {
                "counter": 0
            },
            "kv_rangefeed_budget_allocation_failed": {
                "counter": 0
            },
            "kv_rangefeed_catchup_scan_nanos": {
                "counter": 4840834
            },
            "kv_replica_circuit_breaker_num_tripped_events": {
                "counter": 0
            },
            "kv_replica_circuit_breaker_num_tripped_replicas": {
                "value": 0
            },
            "kv_tenant_rate_limit_current_blocked": {
                "value": 0
            },
            "kv_tenant_rate_limit_num_tenants": {
                "value": 0
            },
            "kv_tenant_rate_limit_read_bytes_admitted": {
                "counter": 0
            },
            "kv_tenant_rate_limit_read_requests_admitted": {
                "counter": 0
            },
            "kv_tenant_rate_limit_write_bytes_admitted": {
                "counter": 0
            },
            "kv_tenant_rate_limit_write_requests_admitted": {
                "counter": 0
            },
            "labels": {
                "instance": "elastic-package-service_cockroachdb_1:8080",
                "job": "prometheus",
                "store": "1"
            },
            "leases_epoch": {
                "value": 0
            },
            "leases_error": {
                "counter": 0
            },
            "leases_expiration": {
                "value": 0
            },
            "leases_success": {
                "counter": 28
            },
            "leases_transfers_error": {
                "counter": 0
            },
            "leases_transfers_success": {
                "counter": 0
            },
            "livebytes": {
                "value": 248040
            },
            "livecount": {
                "value": 1679
            },
            "queue_consistency_pending": {
                "value": 0
            },
            "queue_consistency_process_failure": {
                "counter": 0
            },
            "queue_consistency_process_success": {
                "counter": 9
            },
            "queue_consistency_processingnanos": {
                "counter": 490621584
            },
            "queue_gc_info_abortspanconsidered": {
                "counter": 0
            },
            "queue_gc_info_abortspangcnum": {
                "counter": 0
            },
            "queue_gc_info_abortspanscanned": {
                "counter": 0
            },
            "queue_gc_info_intentsconsidered": {
                "counter": 0
            },
            "queue_gc_info_intenttxns": {
                "counter": 0
            },
            "queue_gc_info_numkeysaffected": {
                "counter": 0
            },
            "queue_gc_info_pushtxn": {
                "counter": 0
            },
            "queue_gc_info_resolvefailed": {
                "counter": 0
            },
            "queue_gc_info_resolvesuccess": {
                "counter": 0
            },
            "queue_gc_info_resolvetotal": {
                "counter": 0
            },
            "queue_gc_info_transactionresolvefailed": {
                "counter": 0
            },
            "queue_gc_info_transactionspangcaborted": {
                "counter": 0
            },
            "queue_gc_info_transactionspangccommitted": {
                "counter": 0
            },
            "queue_gc_info_transactionspangcpending": {
                "counter": 0
            },
            "queue_gc_info_transactionspangcstaging": {
                "counter": 0
            },
            "queue_gc_info_transactionspanscanned": {
                "counter": 0
            },
            "queue_gc_pending": {
                "value": 0
            },
            "queue_gc_process_failure": {
                "counter": 0
            },
            "queue_gc_process_success": {
                "counter": 0
            },
            "queue_gc_processingnanos": {
                "counter": 0
            },
            "queue_merge_pending": {
                "value": 41
            },
            "queue_merge_process_failure": {
                "counter": 0
            },
            "queue_merge_process_success": {
                "counter": 0
            },
            "queue_merge_processingnanos": {
                "counter": 21611042
            },
            "queue_merge_purgatory": {
                "value": 0
            },
            "queue_raftlog_pending": {
                "value": 0
            },
            "queue_raftlog_process_failure": {
                "counter": 0
            },
            "queue_raftlog_process_success": {
                "counter": 3
            },
            "queue_raftlog_processingnanos": {
                "counter": 48402543
            },
            "queue_raftsnapshot_pending": {
                "value": 0
            },
            "queue_raftsnapshot_process_failure": {
                "counter": 0
            },
            "queue_raftsnapshot_process_success": {
                "counter": 0
            },
            "queue_raftsnapshot_processingnanos": {
                "counter": 0
            },
            "queue_replicagc_pending": {
                "value": 0
            },
            "queue_replicagc_process_failure": {
                "counter": 0
            },
            "queue_replicagc_process_success": {
                "counter": 0
            },
            "queue_replicagc_processingnanos": {
                "counter": 0
            },
            "queue_replicagc_removereplica": {
                "counter": 0
            },
            "queue_replicate_addnonvoterreplica": {
                "counter": 0
            },
            "queue_replicate_addreplica": {
                "counter": 0
            },
            "queue_replicate_addvoterreplica": {
                "counter": 0
            },
            "queue_replicate_nonvoterpromotions": {
                "counter": 0
            },
            "queue_replicate_pending": {
                "value": 0
            },
            "queue_replicate_process_failure": {
                "counter": 26
            },
            "queue_replicate_process_success": {
                "counter": 0
            },
            "queue_replicate_processingnanos": {
                "counter": 157329207
            },
            "queue_replicate_purgatory": {
                "value": 24
            },
            "queue_replicate_rebalancenonvoterreplica": {
                "counter": 0
            },
            "queue_replicate_rebalancereplica": {
                "counter": 0
            },
            "queue_replicate_rebalancevoterreplica": {
                "counter": 0
            },
            "queue_replicate_removedeadnonvoterreplica": {
                "counter": 0
            },
            "queue_replicate_removedeadreplica": {
                "counter": 0
            },
            "queue_replicate_removedeadvoterreplica": {
                "counter": 0
            },
            "queue_replicate_removedecommissioningnonvoterreplica": {
                "counter": 0
            },
            "queue_replicate_removedecommissioningreplica": {
                "counter": 0
            },
            "queue_replicate_removedecommissioningvoterreplica": {
                "counter": 0
            },
            "queue_replicate_removelearnerreplica": {
                "counter": 0
            },
            "queue_replicate_removenonvoterreplica": {
                "counter": 0
            },
            "queue_replicate_removereplica": {
                "counter": 0
            },
            "queue_replicate_removevoterreplica": {
                "counter": 0
            },
            "queue_replicate_transferlease": {
                "counter": 0
            },
            "queue_replicate_voterdemotions": {
                "counter": 0
            },
            "queue_split_pending": {
                "value": 0
            },
            "queue_split_process_failure": {
                "counter": 0
            },
            "queue_split_process_success": {
                "counter": 0
            },
            "queue_split_processingnanos": {
                "counter": 0
            },
            "queue_split_purgatory": {
                "value": 0
            },
            "queue_tsmaintenance_pending": {
                "value": 0
            },
            "queue_tsmaintenance_process_failure": {
                "counter": 0
            },
            "queue_tsmaintenance_process_success": {
                "counter": 1
            },
            "queue_tsmaintenance_processingnanos": {
                "counter": 33299709
            },
            "raft_commandsapplied": {
                "counter": 330
            },
            "raft_enqueued_pending": {
                "value": 0
            },
            "raft_entrycache_accesses": {
                "counter": 55
            },
            "raft_entrycache_bytes": {
                "value": 131713
            },
            "raft_entrycache_hits": {
                "counter": 3
            },
            "raft_entrycache_size": {
                "value": 300
            },
            "raft_heartbeats_pending": {
                "value": 0
            },
            "raft_process_applycommitted_latency": {
                "histogram": {
                    "counts": [
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0
                    ],
                    "values": [
                        27647.5,
                        78847,
                        106495,
                        112639,
                        116735,
                        122879,
                        133119,
                        143359,
                        151551,
                        159743,
                        167935,
                        176127,
                        184319,
                        192511,
                        200703,
                        208895,
                        217087,
                        225279,
                        233471,
                        241663,
                        249855,
                        258047,
                        270335,
                        286719,
                        303103,
                        319487,
                        335871,
                        352255,
                        368639,
                        385023,
                        401407,
                        417791,
                        434175,
                        450559,
                        466943,
                        483327,
                        499711,
                        516095,
                        540671,
                        573439,
                        606207,
                        655359,
                        704511,
                        753663,
                        802815,
                        835583,
                        868351,
                        901119,
                        933887,
                        966655,
                        1015807,
                        1081343,
                        1146879,
                        1212415,
                        1277951,
                        1441791,
                        1638399,
                        1769471,
                        1933311,
                        2129919,
                        2293759,
                        2490367,
                        2818047,
                        3080191,
                        3407871,
                        3932159,
                        4456447,
                        4980735,
                        5373951,
                        5898239,
                        7077887,
                        11010047,
                        14417919,
                        16252927,
                        18350079,
                        21495807,
                        25690111,
                        27787263,
                        28835839,
                        30408703
                    ]
                }
            },
            "raft_process_commandcommit_latency": {
                "histogram": {
                    "counts": [
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0
                    ],
                    "values": [
                        21503.5,
                        48127,
                        63487,
                        75775,
                        79871,
                        83967,
                        88063,
                        92159,
                        96255,
                        100351,
                        104447,
                        108543,
                        112639,
                        116735,
                        120831,
                        124927,
                        129023,
                        135167,
                        143359,
                        151551,
                        159743,
                        167935,
                        176127,
                        184319,
                        192511,
                        200703,
                        208895,
                        217087,
                        225279,
                        233471,
                        241663,
                        249855,
                        258047,
                        270335,
                        286719,
                        303103,
                        319487,
                        335871,
                        352255,
                        368639,
                        385023,
                        401407,
                        417791,
                        434175,
                        450559,
                        466943,
                        483327,
                        507903,
                        540671,
                        573439,
                        622591,
                        671743,
                        704511,
                        737279,
                        802815,
                        868351,
                        901119,
                        933887,
                        983039,
                        1097727,
                        1245183,
                        1507327,
                        2097151,
                        3014655,
                        3670015,
                        4259839,
                        4980735,
                        5373951,
                        5636095,
                        8912895,
                        13369343,
                        15728639,
                        17825791,
                        23068671,
                        28311551,
                        31457279
                    ]
                }
            },
            "raft_process_handleready_latency": {
                "histogram": {
                    "counts": [
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0
                    ],
                    "values": [
                        376831.5,
                        999423,
                        1277951,
                        1343487,
                        1409023,
                        1474559,
                        1540095,
                        1605631,
                        1671167,
                        1736703,
                        1802239,
                        1867775,
                        1933311,
                        1998847,
                        2064383,
                        2162687,
                        2293759,
                        2424831,
                        2555903,
                        2686975,
                        2818047,
                        2949119,
                        3080191,
                        3211263,
                        3342335,
                        3473407,
                        3604479,
                        3735551,
                        3866623,
                        3997695,
                        4128767,
                        4325375,
                        4587519,
                        4849663,
                        5111807,
                        5373951,
                        5636095,
                        5898239,
                        6160383,
                        6422527,
                        6815743,
                        7208959,
                        7602175,
                        7995391,
                        8257535,
                        8650751,
                        9175039,
                        9699327,
                        11534335,
                        13369343,
                        14155775,
                        15728639,
                        17301503,
                        20447231,
                        24117247,
                        28835839,
                        37224447,
                        42991615,
                        48234495,
                        66060287,
                        90177535,
                        117440511,
                        155189247,
                        218103807
                    ]
                }
            },
            "raft_process_logcommit_latency": {
                "histogram": {
                    "counts": [
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0
                    ],
                    "values": [
                        376831.5,
                        819199,
                        901119,
                        933887,
                        966655,
                        999423,
                        1032191,
                        1081343,
                        1146879,
                        1212415,
                        1277951,
                        1343487,
                        1409023,
                        1474559,
                        1540095,
                        1605631,
                        1671167,
                        1736703,
                        1802239,
                        1867775,
                        1933311,
                        1998847,
                        2064383,
                        2162687,
                        2293759,
                        2424831,
                        2555903,
                        2686975,
                        2818047,
                        2949119,
                        3080191,
                        3211263,
                        3342335,
                        3473407,
                        3604479,
                        3735551,
                        3866623,
                        3997695,
                        4128767,
                        4325375,
                        4587519,
                        4849663,
                        5111807,
                        5373951,
                        5898239,
                        6422527,
                        6684671,
                        6946815,
                        7471103,
                        8650751,
                        9699327,
                        11010047,
                        12320767,
                        13631487,
                        14942207,
                        15466495,
                        19398655,
                        36700159,
                        75497471,
                        117440511,
                        138412031,
                        150994943
                    ]
                }
            },
            "raft_process_tickingnanos": {
                "counter": 18037084
            },
            "raft_process_workingnanos": {
                "counter": 1726085499
            },
            "raft_rcvd_app": {
                "counter": 0
            },
            "raft_rcvd_appresp": {
                "counter": 0
            },
            "raft_rcvd_dropped": {
                "counter": 0
            },
            "raft_rcvd_heartbeat": {
                "counter": 0
            },
            "raft_rcvd_heartbeatresp": {
                "counter": 0
            },
            "raft_rcvd_prevote": {
                "counter": 0
            },
            "raft_rcvd_prevoteresp": {
                "counter": 0
            },
            "raft_rcvd_prop": {
                "counter": 0
            },
            "raft_rcvd_snap": {
                "counter": 0
            },
            "raft_rcvd_timeoutnow": {
                "counter": 0
            },
            "raft_rcvd_transferleader": {
                "counter": 0
            },
            "raft_rcvd_vote": {
                "counter": 0
            },
            "raft_rcvd_voteresp": {
                "counter": 0
            },
            "raft_scheduler_latency": {
                "histogram": {
                    "counts": [
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0
                    ],
                    "values": [
                        4095.5,
                        11519,
                        17151,
                        19967,
                        20991,
                        22015,
                        23039,
                        24575,
                        26111,
                        27135,
                        28159,
                        29183,
                        30207,
                        31231,
                        32255,
                        33791,
                        35839,
                        37887,
                        39935,
                        41983,
                        44031,
                        46079,
                        48127,
                        50175,
                        52223,
                        54271,
                        56319,
                        58367,
                        60415,
                        62463,
                        64511,
                        67583,
                        71679,
                        75775,
                        79871,
                        83967,
                        88063,
                        92159,
                        96255,
                        104447,
                        112639,
                        116735,
                        120831,
                        124927,
                        129023,
                        135167,
                        143359,
                        151551,
                        159743,
                        167935,
                        176127,
                        184319,
                        192511,
                        200703,
                        208895,
                        217087,
                        225279,
                        233471,
                        241663,
                        249855,
                        266239,
                        286719,
                        303103,
                        319487,
                        335871,
                        352255,
                        368639,
                        393215,
                        425983,
                        450559,
                        466943,
                        483327,
                        540671,
                        606207,
                        655359,
                        704511,
                        737279,
                        770047,
                        819199,
                        868351,
                        933887,
                        1015807,
                        1081343,
                        1179647,
                        1277951,
                        1343487,
                        1409023,
                        1474559,
                        1540095,
                        1605631,
                        1671167,
                        1736703,
                        1802239,
                        1867775,
                        1933311,
                        1998847,
                        2064383,
                        2162687,
                        2293759,
                        2424831,
                        2555903,
                        2686975,
                        2818047,
                        2949119,
                        3342335,
                        3735551,
                        3932159,
                        4259839,
                        4849663,
                        5373951,
                        5636095,
                        5898239,
                        6160383,
                        6553599,
                        7077887,
                        9437183,
                        14155775,
                        71303167,
                        146800639,
                        209715199
                    ]
                }
            },
            "raft_ticks": {
                "counter": 45
            },
            "raft_timeoutcampaign": {
                "counter": 0
            },
            "raftlog_behind": {
                "value": 0
            },
            "raftlog_truncated": {
                "counter": 30
            },
            "range_adds": {
                "counter": 0
            },
            "range_merges": {
                "counter": 0
            },
            "range_raftleadertransfers": {
                "counter": 0
            },
            "range_recoveries": {
                "counter": 0
            },
            "range_removes": {
                "counter": 0
            },
            "range_snapshots_applied_initial": {
                "counter": 0
            },
            "range_snapshots_applied_non_voter": {
                "counter": 0
            },
            "range_snapshots_applied_voter": {
                "counter": 0
            },
            "range_snapshots_generated": {
                "counter": 0
            },
            "range_snapshots_rcvd_bytes": {
                "counter": 0
            },
            "range_snapshots_sent_bytes": {
                "counter": 0
            },
            "range_splits": {
                "counter": 0
            },
            "ranges": {
                "value": 0
            },
            "ranges_overreplicated": {
                "value": 0
            },
            "ranges_unavailable": {
                "value": 0
            },
            "ranges_underreplicated": {
                "value": 0
            },
            "rebalancing_lease_transfers": {
                "counter": 0
            },
            "rebalancing_queriespersecond": {
                "value": 0
            },
            "rebalancing_range_rebalances": {
                "counter": 0
            },
            "rebalancing_writespersecond": {
                "value": 0
            },
            "replicas": {
                "value": 44
            },
            "replicas_leaders": {
                "value": 0
            },
            "replicas_leaders_not_leaseholders": {
                "value": 0
            },
            "replicas_leaseholders": {
                "value": 0
            },
            "replicas_quiescent": {
                "value": 0
            },
            "replicas_reserved": {
                "value": 0
            },
            "replicas_uninitialized": {
                "value": 0
            },
            "requests_backpressure_split": {
                "value": 0
            },
            "requests_slow_latch": {
                "value": 0
            },
            "requests_slow_lease": {
                "value": 0
            },
            "requests_slow_raft": {
                "value": 0
            },
            "rocksdb_block_cache_hits": {
                "value": 0
            },
            "rocksdb_block_cache_misses": {
                "value": 0
            },
            "rocksdb_block_cache_pinned_usage": {
                "value": 0
            },
            "rocksdb_block_cache_usage": {
                "value": 0
            },
            "rocksdb_bloom_filter_prefix_checked": {
                "value": 0
            },
            "rocksdb_bloom_filter_prefix_useful": {
                "value": 0
            },
            "rocksdb_compacted_bytes_read": {
                "value": 0
            },
            "rocksdb_compacted_bytes_written": {
                "value": 0
            },
            "rocksdb_compactions": {
                "value": 0
            },
            "rocksdb_encryption_algorithm": {
                "value": 0
            },
            "rocksdb_estimated_pending_compaction": {
                "value": 0
            },
            "rocksdb_flushed_bytes": {
                "value": 0
            },
            "rocksdb_flushes": {
                "value": 0
            },
            "rocksdb_ingested_bytes": {
                "value": 0
            },
            "rocksdb_memtable_total_size": {
                "value": 0
            },
            "rocksdb_num_sstables": {
                "value": 0
            },
            "rocksdb_read_amplification": {
                "value": 0
            },
            "rocksdb_table_readers_mem_estimate": {
                "value": 0
            },
            "storage_disk_slow": {
                "value": 0
            },
            "storage_disk_stalled": {
                "value": 0
            },
            "storage_l0_num_files": {
                "value": 0
            },
            "storage_l0_sublevels": {
                "value": 0
            },
            "storage_marked_for_compaction_files": {
                "value": 0
            },
            "storage_write_stalls": {
                "value": 0
            },
            "sysbytes": {
                "value": 8716
            },
            "syscount": {
                "value": 212
            },
            "totalbytes": {
                "value": 250992
            },
            "tscache_skl_pages": {
                "value": 1
            },
            "tscache_skl_rotations": {
                "counter": 0
            },
            "txn_commit_waits_before_commit_trigger": {
                "counter": 0
            },
            "txnrecovery_attempts_pending": {
                "value": 0
            },
            "txnrecovery_attempts_total": {
                "counter": 0
            },
            "txnrecovery_failures": {
                "counter": 0
            },
            "txnrecovery_successes_aborted": {
                "counter": 0
            },
            "txnrecovery_successes_committed": {
                "counter": 0
            },
            "txnrecovery_successes_pending": {
                "counter": 0
            },
            "txnwaitqueue_deadlocks_total": {
                "counter": 0
            },
            "txnwaitqueue_pushee_waiting": {
                "value": 0
            },
            "txnwaitqueue_pusher_slow": {
                "value": 0
            },
            "txnwaitqueue_pusher_wait_time": {
                "histogram": {
                    "counts": [
                        0
                    ],
                    "values": [
                        0
                    ]
                }
            },
            "txnwaitqueue_pusher_waiting": {
                "value": 0
            },
            "txnwaitqueue_query_wait_time": {
                "histogram": {
                    "counts": [
                        0
                    ],
                    "values": [
                        0
                    ]
                }
            },
            "txnwaitqueue_query_waiting": {
                "value": 0
            },
            "valbytes": {
                "value": 168360
            },
            "valcount": {
                "value": 1750
            }
        }
    },
    "data_stream": {
        "dataset": "cockroachdb.status",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "19de6249-945f-46da-9464-383664c3adaf",
        "snapshot": false,
        "version": "8.4.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "cockroachdb.status",
        "duration": 248296459,
        "ingested": "2022-09-06T09:50:55Z",
        "module": "prometheus"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "5016511f0829451ea244f458eebf2212",
        "ip": [
            "172.18.0.7"
        ],
        "mac": [
            "02-42-AC-1F-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.104-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "collector",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service_cockroachdb_1:8080/_status/vars",
        "type": "prometheus"
    }
}
```

