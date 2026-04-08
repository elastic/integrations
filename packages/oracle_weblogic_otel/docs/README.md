# Oracle WebLogic Server OpenTelemetry Assets

Oracle WebLogic Server is a Java EE / Jakarta EE application server used to develop, deploy, and run enterprise applications in production environments.

These assets provide dashboards, alert rules, and SLO templates built on metrics collected by the [OpenTelemetry JMX Scraper](https://github.com/open-telemetry/opentelemetry-java-contrib/tree/main/jmx-scraper) with a custom WebLogic [metrics definition](https://github.com/open-telemetry/opentelemetry-java-instrumentation/tree/main/instrumentation/jmx-metrics). They cover JVM heap utilization, thread pool health, JTA transaction integrity, work manager performance, and server stability.

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

Configure the [OpenTelemetry JMX Scraper](https://github.com/open-telemetry/opentelemetry-java-contrib/tree/main/jmx-scraper) as a standalone process to collect metrics from your WebLogic Server instance, and the OpenTelemetry Collector (or EDOT Collector) with an OTLP receiver to forward those metrics to Elasticsearch.

Placeholders used in the configuration below:

- `<WEBLOGIC_HOST>` — Hostname or IP address of the WebLogic Server instance (for example, `weblogic.example.com`)
- `<WEBLOGIC_PORT>` — T3 protocol listen port for the WebLogic instance (for example, `7001`)
- `<COLLECTOR_HOST>` — Hostname or IP address where the OpenTelemetry Collector is running (for example, `localhost`)
- `<ES_ENDPOINT>` — Your Elasticsearch endpoint URL (for example, `https://my-deployment.es.us-central1.gcp.cloud.es.io:443`)
- `${env:WEBLOGIC_USERNAME}` — Environment variable containing the WebLogic monitoring user's username
- `${env:WEBLOGIC_PASSWORD}` — Environment variable containing the WebLogic monitoring user's password
- `${env:ES_API_KEY}` — Environment variable containing your Elasticsearch API key
- `/path/to/weblogic.yaml` — Path to the custom WebLogic YAML metrics definition file

#### JMX Scraper

Download the [JMX Scraper JAR](https://github.com/open-telemetry/opentelemetry-java-contrib/releases/latest/download/opentelemetry-jmx-scraper.jar) and run it as a standalone process:

```bash
java -jar /opt/opentelemetry-jmx-scraper.jar \
  -config \
  otel.jmx.service.url=service:jmx:t3://<WEBLOGIC_HOST>:<WEBLOGIC_PORT>/jndi/weblogic.management.mbeanservers.runtime \
  otel.jmx.config=/path/to/weblogic.yaml \
  otel.jmx.username=${WEBLOGIC_USERNAME} \
  otel.jmx.password=${WEBLOGIC_PASSWORD} \
  otel.metric.export.interval=60s \
  otel.exporter.otlp.endpoint=http://<COLLECTOR_HOST>:4317
```

The `weblogic.yaml` file contains the custom [YAML metrics definition](https://github.com/open-telemetry/opentelemetry-java-instrumentation/tree/main/instrumentation/jmx-metrics) that maps WebLogic runtime MBeans to the `weblogic.*` metrics used by these assets. WebLogic is not yet a built-in target system in the JMX Scraper (see [upstream request](https://github.com/open-telemetry/opentelemetry-java-instrumentation/issues/14994)).

> **Note**: The T3 protocol requires the WebLogic T3 thin client library (`wlthint3client.jar`) in the classpath. If needed, use `-cp` instead of `-jar`:
>
> ```bash
> java -cp /opt/opentelemetry-jmx-scraper.jar:/path/to/wlthint3client.jar \
>   io.opentelemetry.contrib.jmxscraper.JmxScraper \
>   -config otel.jmx.config=/path/to/weblogic.yaml ...
> ```

#### OpenTelemetry Collector

Configure the OpenTelemetry Collector (or EDOT Collector) to receive metrics from the JMX Scraper via OTLP and export them to Elasticsearch:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

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
      receivers: [otlp]
      exporters: [elasticsearch/otel]
```

> **Note**: To monitor multiple WebLogic Server instances, run additional JMX Scraper processes, each pointing to a different host and port.

## Reference

### Metrics

Refer to the [JMX Scraper configuration reference](https://github.com/open-telemetry/opentelemetry-java-contrib/tree/main/jmx-scraper#configuration-reference) for details on the scraper configuration options.

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

> **Note**: SLO templates require Elastic Stack version 9.4.0 or later.

| SLO | Target | Window | Description |
|-----|--------|--------|-------------|
| **JTA transaction commit rate** | 99.5% | 30-day rolling | Tracks the ratio of committed to total JTA transactions, targeting 99.5% of 1-minute windows maintaining at least a 95% commit rate. |
| **Thread pool low pending requests** | 99.5% | 30-day rolling | Tracks pending requests in the self-tuning thread pool, targeting 99.5% of 1-minute windows with an average of 1 or fewer pending requests. |
