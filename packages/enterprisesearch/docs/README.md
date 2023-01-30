# Enterprise search

The `enterprisesearch` package collects metrics of Enterprise search. 

## Metrics

### Usage for Stack Monitoring

The `enterprisesearch` package can be used to collect metrics shown in our Stack Monitoring
UI in Kibana.

### Health

Fetch and ingest Enterprise Search solution health information from the [Health API](https://www.elastic.co/guide/en/enterprise-search/current/monitoring-apis.html#health-api).

An example event for `health` looks as following:

```json
{
    "@timestamp": "2023-01-04T22:40:58.396Z",
    "agent": {
        "ephemeral_id": "48eb4316-38c7-4d0f-922b-bfb6f3089a76",
        "id": "1c17c52c-7d62-45f1-9132-758015a03e1b",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.5.0"
    },
    "data_stream": {
        "dataset": "enterprisesearch.stack_monitoring.health",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "1c17c52c-7d62-45f1-9132-758015a03e1b",
        "snapshot": false,
        "version": "8.5.0"
    },
    "enterprisesearch": {
        "cluster_uuid": "ecj1cwynSzOnzeaeoEqvwg",
        "health": {
            "crawler": {
                "workers": {
                    "active": 0,
                    "available": 20,
                    "pool_size": 20
                }
            },
            "jvm": {
                "gc": {
                    "collection_count": 14,
                    "collection_time": {
                        "ms": 729
                    }
                },
                "memory_usage": {
                    "heap_committed": {
                        "bytes": 2147483648
                    },
                    "heap_init": {
                        "bytes": 2147483648
                    },
                    "heap_max": {
                        "bytes": 2147483648
                    },
                    "heap_used": {
                        "bytes": 463363072
                    },
                    "non_heap_committed": {
                        "bytes": 223854592
                    },
                    "non_heap_init": {
                        "bytes": 7667712
                    },
                    "object_pending_finalization_count": 0
                },
                "threads": {
                    "current": 44,
                    "daemon": 32,
                    "max": 45,
                    "total_started": 46
                },
                "version": "11.0.16.1"
            },
            "name": "09337f10efb8",
            "process": {
                "filebeat": {
                    "pid": 601,
                    "restart_count": 0,
                    "time_since_last_restart": {
                        "sec": -1
                    }
                },
                "pid": 7,
                "uptime": {
                    "sec": 77981
                }
            },
            "version": {
                "build_hash": "e8a1c7e0c5d88bb8673bf10e7be7a419718c6358",
                "number": "8.5.0"
            }
        }
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "enterprisesearch.stack_monitoring.health",
        "duration": 26344700,
        "ingested": "2023-01-04T22:40:59Z",
        "module": "enterprisesearch"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "66392b0697b84641af8006d87aeb89f1",
        "ip": [
            "172.20.0.7"
        ],
        "mac": [
            "02-42-AC-14-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.47-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "health",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service_enterprisesearch_1:3002/api/ent/v1/internal/health",
        "type": "enterprisesearch"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| agent.ephemeral_id | Ephemeral identifier of this agent (if one exists). This id normally changes across restarts, but `agent.id` does not. | keyword |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| enterprisesearch.cluster_uuid | Cluster UUID for the Elasticsearch cluster used as the data store for Enterprise Search. | keyword |
| enterprisesearch.health.crawler.workers.active | Number of active workers. | long |
| enterprisesearch.health.crawler.workers.available | Number of available workers. | long |
| enterprisesearch.health.crawler.workers.pool_size | Workers pool size. | long |
| enterprisesearch.health.jvm.gc.collection_count | Total number of Java garbage collector invocations since the start of the process | long |
| enterprisesearch.health.jvm.gc.collection_time.ms | Total time spent running Java garbage collector since the start of the process | long |
| enterprisesearch.health.jvm.memory_usage.heap_committed.bytes | Committed heap to the JVM in bytes. | long |
| enterprisesearch.health.jvm.memory_usage.heap_init.bytes | Heap init used by the JVM in bytes. | long |
| enterprisesearch.health.jvm.memory_usage.heap_max.bytes | Max heap used by the JVM in bytes | long |
| enterprisesearch.health.jvm.memory_usage.heap_used.bytes | Heap used by the JVM in bytes. | long |
| enterprisesearch.health.jvm.memory_usage.non_heap_committed.bytes | Non-Heap committed memory used by the JVM in bytes. | long |
| enterprisesearch.health.jvm.memory_usage.non_heap_init.bytes | Non-Heap initial memory used by the JVM in bytes. | long |
| enterprisesearch.health.jvm.memory_usage.object_pending_finalization_count | Displays the approximate number of objects for which finalization is pending. | long |
| enterprisesearch.health.jvm.threads.current | Current number of live threads. | long |
| enterprisesearch.health.jvm.threads.daemon | Current number of live daemon threads. | long |
| enterprisesearch.health.jvm.threads.max | Peak live thread count since the JVM started or the peak was reset. | long |
| enterprisesearch.health.jvm.threads.total_started | Total number of threads created and/or started since the JVM started. | long |
| enterprisesearch.health.jvm.version | JVM version used to run Enterprise Search | keyword |
| enterprisesearch.health.name | Host name for the Enterprise Search node | keyword |
| enterprisesearch.health.process.filebeat.pid | Process ID for the embedded Filebeat instance | long |
| enterprisesearch.health.process.filebeat.restart_count | Number of times embedded Filebeat instance had to be restarted due to some issues | long |
| enterprisesearch.health.process.filebeat.time_since_last_restart.sec | Time since the last embedded Filebeat instance restart (-1 if never restarted) | long |
| enterprisesearch.health.process.pid | Process ID for the Enterprise Search instance | long |
| enterprisesearch.health.process.uptime.sec | Process uptime for the Enterprise Search instance | long |
| enterprisesearch.health.version.build_hash | A unique build hash for the Enterprise Search package | keyword |
| enterprisesearch.health.version.number | Enterprise Search version number using the semantic versioning format | keyword |
| error.message | Error message. | match_only_text |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


### Stats

Fetch and ingest Enterprise Search solution statistics information from the [Stats API](https://www.elastic.co/guide/en/enterprise-search/current/monitoring-apis.html#stats-api).

An example event for `stats` looks as following:

```json
{
    "@timestamp": "2023-01-04T22:43:01.326Z",
    "agent": {
        "ephemeral_id": "48eb4316-38c7-4d0f-922b-bfb6f3089a76",
        "id": "1c17c52c-7d62-45f1-9132-758015a03e1b",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.5.0"
    },
    "data_stream": {
        "dataset": "enterprisesearch.stack_monitoring.stats",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "1c17c52c-7d62-45f1-9132-758015a03e1b",
        "snapshot": false,
        "version": "8.5.0"
    },
    "enterprisesearch": {
        "cluster_uuid": "lrSOQ4j8QWSJqD_UrBFqrQ",
        "stats": {
            "connectors": {
                "job_store": {
                    "job_types": {
                        "delete": 0,
                        "full": 0,
                        "incremental": 0,
                        "permissions": 0
                    },
                    "waiting": 0,
                    "working": 0
                },
                "pool": {
                    "extract_worker_pool": {
                        "busy": 1,
                        "idle": 0,
                        "queue_depth": 0,
                        "size": 1,
                        "total_completed": 1,
                        "total_scheduled": 1
                    },
                    "publish_worker_pool": {
                        "busy": 0,
                        "idle": 0,
                        "queue_depth": 0,
                        "size": 0,
                        "total_completed": 0,
                        "total_scheduled": 0
                    },
                    "subextract_worker_pool": {
                        "busy": 0,
                        "idle": 0,
                        "queue_depth": 0,
                        "size": 0,
                        "total_completed": 0,
                        "total_scheduled": 0
                    }
                }
            },
            "crawler": {
                "global": {
                    "crawl_requests": {
                        "active": 0,
                        "failed": 0,
                        "pending": 0,
                        "successful": 0
                    }
                },
                "node": {
                    "active_threads": 0,
                    "pages_visited": 0,
                    "queue_size": {
                        "primary": 0,
                        "purge": 0
                    },
                    "status_codes": {},
                    "urls_allowed": 0,
                    "urls_denied": {},
                    "workers": {
                        "active": 0,
                        "available": 20,
                        "pool_size": 20
                    }
                }
            },
            "http": {
                "connections": {
                    "current": 3,
                    "max": 3,
                    "total": 34
                },
                "network": {
                    "received": {
                        "bytes": 3875,
                        "bytes_per_sec": 129
                    },
                    "sent": {
                        "bytes": 23281,
                        "bytes_per_sec": 777
                    }
                },
                "request_duration": {
                    "max": {
                        "ms": 497
                    },
                    "mean": {
                        "ms": 39
                    },
                    "std_dev": {
                        "ms": 68
                    }
                },
                "responses": {
                    "1xx": 0,
                    "2xx": 8,
                    "3xx": 31,
                    "4xx": 0,
                    "5xx": 0
                }
            },
            "product_usage": {
                "app_search": {
                    "total_engines": 0
                },
                "workplace_search": {
                    "total_org_sources": 0,
                    "total_private_sources": 0
                }
            },
            "queues": {
                "engine_destroyer": {
                    "count": 0
                },
                "failed": {
                    "count": 0
                },
                "mailer": {
                    "count": 0
                },
                "process_crawl": {
                    "count": 0
                }
            }
        }
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "enterprisesearch.stack_monitoring.stats",
        "duration": 123613600,
        "ingested": "2023-01-04T22:43:02Z",
        "module": "enterprisesearch"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "66392b0697b84641af8006d87aeb89f1",
        "ip": [
            "172.20.0.7"
        ],
        "mac": [
            "02-42-AC-14-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.47-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "stats",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service_enterprisesearch_1:3002/api/ent/v1/internal/stats",
        "type": "enterprisesearch"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| agent.ephemeral_id | Ephemeral identifier of this agent (if one exists). This id normally changes across restarts, but `agent.id` does not. | keyword |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| enterprisesearch.cluster_uuid | Cluster UUID for the Elasticsearch cluster used as the data store for Enterprise Search. | keyword |
| enterprisesearch.stats.connectors.job_store.job_types.delete | Number of delete jobs in the jobs store. | long |
| enterprisesearch.stats.connectors.job_store.job_types.full | Number of full sync jobs in the jobs store. | long |
| enterprisesearch.stats.connectors.job_store.job_types.incremental | Number of incremental sync jobs in the jobs store. | long |
| enterprisesearch.stats.connectors.job_store.job_types.permissions | Number of permissions sync jobs in the jobs store. | long |
| enterprisesearch.stats.connectors.job_store.waiting | Number of connectors jobs waiting to be processed. | long |
| enterprisesearch.stats.connectors.job_store.working | Number of connectors jobs currently being processed. | long |
| enterprisesearch.stats.connectors.pool.extract_worker_pool.busy | Number of busy workers. | long |
| enterprisesearch.stats.connectors.pool.extract_worker_pool.idle | Number of idle workers. | long |
| enterprisesearch.stats.connectors.pool.extract_worker_pool.queue_depth | Number of items waiting to be processed. | long |
| enterprisesearch.stats.connectors.pool.extract_worker_pool.size | Worker pool size. | long |
| enterprisesearch.stats.connectors.pool.extract_worker_pool.total_completed | Number of jobs completed since the start. | long |
| enterprisesearch.stats.connectors.pool.extract_worker_pool.total_scheduled | Number of jobs scheduled since the start. | long |
| enterprisesearch.stats.connectors.pool.publish_worker_pool.busy | Number of busy workers. | long |
| enterprisesearch.stats.connectors.pool.publish_worker_pool.idle | Number of idle workers. | long |
| enterprisesearch.stats.connectors.pool.publish_worker_pool.queue_depth | Number of items waiting to be processed. | long |
| enterprisesearch.stats.connectors.pool.publish_worker_pool.size | Worker pool size. | long |
| enterprisesearch.stats.connectors.pool.publish_worker_pool.total_completed | Number of jobs completed since the start. | long |
| enterprisesearch.stats.connectors.pool.publish_worker_pool.total_scheduled | Number of jobs scheduled since the start. | long |
| enterprisesearch.stats.connectors.pool.subextract_worker_pool.busy | Number of busy workers. | long |
| enterprisesearch.stats.connectors.pool.subextract_worker_pool.idle | Number of idle workers. | long |
| enterprisesearch.stats.connectors.pool.subextract_worker_pool.queue_depth | Number of items waiting to be processed. | long |
| enterprisesearch.stats.connectors.pool.subextract_worker_pool.size | Worker pool size. | long |
| enterprisesearch.stats.connectors.pool.subextract_worker_pool.total_completed | Number of jobs completed since the start. | long |
| enterprisesearch.stats.connectors.pool.subextract_worker_pool.total_scheduled | Number of jobs scheduled since the start. | long |
| enterprisesearch.stats.crawler.global.crawl_requests.active | Total number of crawl requests currently being processed (running crawls). | long |
| enterprisesearch.stats.crawler.global.crawl_requests.failed | Total number of failed crawl requests. | long |
| enterprisesearch.stats.crawler.global.crawl_requests.pending | Total number of crawl requests waiting to be processed. | long |
| enterprisesearch.stats.crawler.global.crawl_requests.successful | Total number of crawl requests that have succeeded. | long |
| enterprisesearch.stats.crawler.node.active_threads | Total number of crawler worker threads currently active on the instance. | long |
| enterprisesearch.stats.crawler.node.pages_visited | Total number of pages visited by the crawler since the instance start. | long |
| enterprisesearch.stats.crawler.node.queue_size.primary | Total number of URLs waiting to be crawled by the instance. | long |
| enterprisesearch.stats.crawler.node.queue_size.purge | Total number of URLs waiting to be checked by the purge crawl phase. | long |
| enterprisesearch.stats.crawler.node.status_codes.200 | Total number of HTTP 200 responses seen by the crawler since the instance start. | long |
| enterprisesearch.stats.crawler.node.status_codes.301 | Total number of HTTP 301 responses seen by the crawler since the instance start. | long |
| enterprisesearch.stats.crawler.node.status_codes.302 | Total number of HTTP 302 responses seen by the crawler since the instance start. | long |
| enterprisesearch.stats.crawler.node.status_codes.400 | Total number of HTTP 400 responses seen by the crawler since the instance start. | long |
| enterprisesearch.stats.crawler.node.status_codes.401 | Total number of HTTP 401 responses seen by the crawler since the instance start. | long |
| enterprisesearch.stats.crawler.node.status_codes.402 | Total number of HTTP 402 responses seen by the crawler since the instance start. | long |
| enterprisesearch.stats.crawler.node.status_codes.403 | Total number of HTTP 403 responses seen by the crawler since the instance start. | long |
| enterprisesearch.stats.crawler.node.status_codes.404 | Total number of HTTP 404 responses seen by the crawler since the instance start. | long |
| enterprisesearch.stats.crawler.node.status_codes.405 | Total number of HTTP 405 responses seen by the crawler since the instance start. | long |
| enterprisesearch.stats.crawler.node.status_codes.410 | Total number of HTTP 410 responses seen by the crawler since the instance start. | long |
| enterprisesearch.stats.crawler.node.status_codes.422 | Total number of HTTP 422 responses seen by the crawler since the instance start. | long |
| enterprisesearch.stats.crawler.node.status_codes.429 | Total number of HTTP 429 responses seen by the crawler since the instance start. | long |
| enterprisesearch.stats.crawler.node.status_codes.500 | Total number of HTTP 500 responses seen by the crawler since the instance start. | long |
| enterprisesearch.stats.crawler.node.status_codes.501 | Total number of HTTP 501 responses seen by the crawler since the instance start. | long |
| enterprisesearch.stats.crawler.node.status_codes.502 | Total number of HTTP 502 responses seen by the crawler since the instance start. | long |
| enterprisesearch.stats.crawler.node.status_codes.503 | Total number of HTTP 503 responses seen by the crawler since the instance start. | long |
| enterprisesearch.stats.crawler.node.status_codes.504 | Total number of HTTP 504 responses seen by the crawler since the instance start. | long |
| enterprisesearch.stats.crawler.node.urls_allowed | Total number of URLs allowed by the crawler during discovery since the instance start. | long |
| enterprisesearch.stats.crawler.node.urls_denied.already_seen | Total number of URLs not followed because of URL de-duplication (each URL is visited only once). | long |
| enterprisesearch.stats.crawler.node.urls_denied.domain_filter_denied | Total number of URLs denied because of an unknown domain. | long |
| enterprisesearch.stats.crawler.node.urls_denied.incorrect_protocol | Total number of URLs with incorrect/invalid/unsupported protocols. | long |
| enterprisesearch.stats.crawler.node.urls_denied.link_too_deep | Total number of URLs not followed due to crawl depth limits. | long |
| enterprisesearch.stats.crawler.node.urls_denied.nofollow | Total number of URLs denied due to a nofollow meta tag or an HTML link attribute. | long |
| enterprisesearch.stats.crawler.node.urls_denied.unsupported_content_type | Total number of URLs denied due to an unsupported content type. | long |
| enterprisesearch.stats.crawler.node.workers.active | Total number of currently active crawl workers (running crawls) for the instance. | long |
| enterprisesearch.stats.crawler.node.workers.available | Total number of currently available (free) crawl workers for the instance. | long |
| enterprisesearch.stats.crawler.node.workers.pool_size | Total size of the crawl workers pool (number of concurrent crawls possible) for the instance. | long |
| enterprisesearch.stats.http.connections.current | Current number of HTTP connections opened to the Enterprise Search instance. | long |
| enterprisesearch.stats.http.connections.max | Maximum number of concurrent HTTP connections open to the Enterprise Search instance since the start. | long |
| enterprisesearch.stats.http.connections.total | Total number of HTTP connections opened to the Enterprise Search instance since the start. | long |
| enterprisesearch.stats.http.network.received.bytes | Total number of bytes received by the Enterprise Search instance since the start. | long |
| enterprisesearch.stats.http.network.received.bytes_per_sec | Average number of bytes received by the Enterprise Search instance per second since the start. | long |
| enterprisesearch.stats.http.network.sent.bytes | Total number of bytes sent by the Enterprise Search instance since the start. | long |
| enterprisesearch.stats.http.network.sent.bytes_per_sec | Average number of bytes sent by the Enterprise Search instance per second since the start. | long |
| enterprisesearch.stats.http.request_duration.max.ms | Longest HTTP connection duration since the start of the instance. | long |
| enterprisesearch.stats.http.request_duration.mean.ms | Average HTTP connection duration since the start of the instance. | long |
| enterprisesearch.stats.http.request_duration.std_dev.ms | Standard deviation for HTTP connection duration values since the start of the instance. | long |
| enterprisesearch.stats.http.responses.1xx | Total number of HTTP requests finished with a 1xx response code since the start of the instance. | long |
| enterprisesearch.stats.http.responses.2xx | Total number of HTTP requests finished with a 2xx response code since the start of the instance. | long |
| enterprisesearch.stats.http.responses.3xx | Total number of HTTP requests finished with a 3xx response code since the start of the instance. | long |
| enterprisesearch.stats.http.responses.4xx | Total number of HTTP requests finished with a 4xx response code since the start of the instance. | long |
| enterprisesearch.stats.http.responses.5xx | Total number of HTTP requests finished with a 5xx response code since the start of the instance. | long |
| enterprisesearch.stats.product_usage.app_search.total_engines | Current number of App Search engines within the deployment. | long |
| enterprisesearch.stats.product_usage.workplace_search.total_org_sources | Current number of Workplace Search org-wide content sources within the deployment. | long |
| enterprisesearch.stats.product_usage.workplace_search.total_private_sources | Current number of Workplace Search private content sources within the deployment. | long |
| enterprisesearch.stats.queues.engine_destroyer.count | Total number of jobs processed via the engine_destroyer queue since the start of the instance. | long |
| enterprisesearch.stats.queues.failed.count | Total number of jobs waiting in the failed queue. | long |
| enterprisesearch.stats.queues.mailer.count | Total number of jobs processed via the mailer queue since the start of the instance. | long |
| enterprisesearch.stats.queues.process_crawl.count | Total number of jobs processed via the process_crawl queue since the start of the instance. | long |
| error.message | Error message. | match_only_text |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |

