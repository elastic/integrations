# Enterprise search

The `enterprisesearch` package collects metrics of Enterprise search. 

## Metrics

### Usage for Stack Monitoring

The `enterprisesearch` package can be used to collect metrics shown in our Stack Monitoring
UI in Kibana.

### Health

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
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


### Stats

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
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


