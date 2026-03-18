# Oracle WebLogic Server OpenTelemetry Assets

Oracle WebLogic Server is a Java EE / Jakarta EE application server used to develop, deploy, and run enterprise applications in production environments.

These assets provide dashboards, alert rules, and SLO templates built on metrics collected by the OpenTelemetry JMX receiver with the `weblogic` target system. They cover JVM heap utilization, thread pool health, JTA transaction integrity, work manager performance, and server stability.

## Compatibility

These assets were tested with OTel Collector Contrib 0.145.0, JMX Scraper 1.53.0, and Oracle WebLogic Server 14.1.2.0.0 (latest GA).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage
the Elastic Stack on your own hardware.

## Setup

### Prerequisites

Oracle WebLogic Server exposes JMX MBeans by default through the T3 protocol. Ensure the following before configuring the collector:

1. The WebLogic Administration Server or Managed Server is running and accessible over the network on its T3 listen port (default `7001`).
2. A WebLogic user account with monitoring privileges exists. The account needs read access to the runtime MBean server. You can use the built-in `Monitor` security role or create a dedicated monitoring user:

```
# In the WebLogic Admin Console:
# Security Realms > myrealm > Users and Groups > Users > New
# Assign the "Monitor" role to the new user
```

3. If you are connecting to a Managed Server directly, ensure the T3 protocol is enabled on that server's listen address and port.

### Configuration

Configure the OpenTelemetry Collector (or EDOT Collector) with the JMX receiver targeting your WebLogic Server instance.

Placeholders used in the configuration below:

- `<WEBLOGIC_HOST>` — Hostname or IP address of the WebLogic Server instance (e.g. `weblogic.example.com`)
- `<WEBLOGIC_PORT>` — T3 protocol listen port for the WebLogic instance (e.g. `7001`)
- `<ES_ENDPOINT>` — Your Elasticsearch endpoint URL (e.g. `https://my-deployment.es.us-central1.gcp.cloud.es.io:443`)
- `${env:WEBLOGIC_USERNAME}` — Environment variable containing the WebLogic monitoring user's username
- `${env:WEBLOGIC_PASSWORD}` — Environment variable containing the WebLogic monitoring user's password
- `${env:ES_API_KEY}` — Environment variable containing your Elasticsearch API key

```yaml
receivers:
  jmx/weblogic:
    jar_path: /opt/opentelemetry-jmx-metrics.jar
    endpoint: service:jmx:t3://<WEBLOGIC_HOST>:<WEBLOGIC_PORT>/jndi/weblogic.management.mbeanservers.runtime
    target_system: weblogic
    username: ${env:WEBLOGIC_USERNAME}
    password: ${env:WEBLOGIC_PASSWORD}
    collection_interval: 60s

exporters:
  elasticsearch/otel:
    endpoints:
      - <ES_ENDPOINT>
    api_key: ${env:ES_API_KEY}
    mapping:
      mode: otel
    logs_dynamic_index:
      enabled: true
    metrics_dynamic_index:
      enabled: true
    traces_dynamic_index:
      enabled: true

service:
  pipelines:
    metrics:
      receivers: [jmx/weblogic]
      exporters: [elasticsearch/otel]
```

> **Note**: To monitor multiple WebLogic Server instances, add additional `jmx/` receiver entries (e.g. `jmx/weblogic_managed1`) each pointing to a different host and port, and include all of them in the metrics pipeline receivers list.

## Reference

### Metrics

Refer to the [metadata.yaml](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/jmxreceiver/metadata.yaml) of the OpenTelemetry JMX receiver for details on the receiver configuration. The WebLogic-specific metrics are defined by the `weblogic` [target system](https://github.com/open-telemetry/opentelemetry-java-contrib/tree/main/jmx-metrics/src/main/resources/target-systems) in the OpenTelemetry Java contrib repository.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[Oracle WebLogic OTel] Overview** | High-level overview of WebLogic Server health covering all golden signals: throughput, heap utilization, transaction commit rate, stuck threads, and server restarts. |
| **[Oracle WebLogic OTel] JVM & Thread Pool** | Deep dive into JVM heap memory and thread pool performance including heap utilization trends, thread state composition, throughput, and pending request queues. |
| **[Oracle WebLogic OTel] Transactions & Work Managers** | JTA transaction health and per-application work manager analysis covering commit, rollback, and abandon rates alongside application-level request processing and stuck threads. |

## Alert rules

| Alert | Trigger | Severity |
|-------|---------|----------|
| **Stuck threads detected** | Any WebLogic work manager reports stuck threads (threads exceeding the stuck thread timeout) | Critical |
| **Server restarts detected** | A WebLogic server instance restart is detected within the evaluation window | Critical |
| **High JVM heap utilization** | JVM heap utilization exceeds the configured threshold on any server instance | High |
| **High thread pool utilization** | Thread pool utilization exceeds the configured threshold on any server instance | High |
| **High JTA transaction error rate** | The ratio of failed transactions (rolled back + abandoned) to total transactions exceeds the threshold | Medium |
| **JTA transactions abandoned** | Abandoned JTA transactions are detected, indicating resources not responding within the transaction timeout | Medium |
| **Hogging threads detected** | Hogging threads are detected in the thread pool, indicating requests executing longer than the stuck thread timer threshold | Medium |
| **High pending request queue** | The thread pool pending request queue depth exceeds the configured threshold | Medium |

## SLO templates

| SLO | Target | Window | Description |
|-----|--------|--------|-------------|
| **JTA transaction commit rate** | 99.5% | 30-day rolling | Tracks the ratio of committed to total JTA transactions, targeting 99.5% of 1-minute windows maintaining at least a 95% commit rate. |
| **Thread pool low pending requests** | 99.5% | 30-day rolling | Tracks pending requests in the self-tuning thread pool, targeting 99.5% of 1-minute windows with an average of 1 or fewer pending requests. |
