# Apache Tomcat Integration

## Overview

[Apache Tomcat](https://tomcat.apache.org/tomcat-10.1-doc/logging.html) is a free and open-source implementation of the jakarta servlet, jakarta expression language, and websocket technologies. It provides a pure java http web server environment in which java code can also run. Thus, it is a java web application server, although not a full JEE application server.

Use the Apache Tomcat integration to:

- Collect metrics related to the cache and request and collect logs related to access, catalina, and localhost.
- Create visualizations to monitor, measure and analyze the usage trend and key data, and derive business insights.
- Create alerts to reduce the MTTD and also the MTTR by referencing relevant logs when troubleshooting an issue.

## Data streams

The Apache Tomcat integration collects logs and metrics data.

Logs help you keep a record of events that happen on your machine. The `Log` data streams collected by Apache Tomcat integration are `access`, `catalina`, and `localhost`, so that users can keep track of the IP addresses of the clients, bytes returned to the client or sent by clients, etc., so that users could monitor and troubleshoot the performance of Java applications.

Metrics give you insight into the statistics of the Apache Tomcat. The `Metric` data streams collected by the Apache Tomcat integration are `cache` and `request`, so that the user can monitor and troubleshoot the performance of the Apache Tomcat instance.

Data streams:
- `access`: Collects information related to overall performance of Java applications.
- `catalina`: Collects information related to the startup and shutdown of the Apache Tomcat application server, the deployment of new applications, or the failure of one or more subsystems.
- `localhost`: Collects information related to Web application activity which is related to HTTP transactions between the application server and the client.
- `cache`: Collects information related to the overall cache of the Apache Tomcat instance.
- `request`: Collects information related to requests of the Apache Tomcat instance.

Note:
- Users can monitor and see the log inside the ingested documents for Apache Tomcat in the `logs-*` index pattern from `Discover`, and for metrics, the index pattern is `metrics-*`.

## Compatibility

This integration has been tested against Apache Tomcat versions `10.1.5`, `9.0.71` and `8.5.85`, and Prometheus version `0.17.2`.

## Prerequisites

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your own hardware.

In order to ingest data from the Apache Tomcat, user must have

* Configured Prometheus in Apache Tomcat instance

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Steps to setup Prometheus

Here are the steps to configure Prometheus in Apache Tomcat instance:

1. Go to `<tomcat_home>/webapps` from Apache Tomcat instance.

2. Please find latest [Prometheus version](https://repo1.maven.org/maven2/io/prometheus/jmx/jmx_prometheus_javaagent/), replace in below command and perform from Apache Tomcat instance: -

```
wget https://repo1.maven.org/maven2/io/prometheus/jmx/jmx_prometheus_javaagent/<prometheus_version>/jmx_prometheus_javaagent-<prometheus_version>.jar
```
3. Create `config.yml` file in `<tomcat_home>/webapps` and paste the following content in `config.yml` file: -

```
rules:
- pattern: ".*"
```
4. Go to `/etc/systemd/system` and add the following content in `tomcat.service` file: -

```
Environment='JAVA_OPTS=-javaagent:<tomcat_home>/webapps/jmx_prometheus_javaagent-<prometheus_version>.jar=<prometheus_port>:/opt/tomcat/webapps/config.yml'
```

5. Run the following commands to reload demon and restart Apache Tomcat instance: -

```
systemctl daemon-reload
systemctl restart tomcat
```

## Steps to configure Filestream input for Access logs

Here are the steps to configure Log format in Apache Tomcat instance:

1. Go to `<tomcat_home>/conf/server.xml` from Apache Tomcat instance.

2. The user can update the log format in the pattern field of the class `org.apache.catalina.valves.AccessLogValve`. Here is an example of the `org.apache.catalina.valves.AccessLogValve` class.

```
<Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
       prefix="localhost_access_log" suffix=".txt"
       pattern='%h %l %u %t "%r" %s %b %A %X %T "%{Referer}i" "%{User-Agent}i" X-Forwarded-For="%{X-Forwarded-For}i"' />
```

3. The supported log formats are:
```
Common Log Format :- '%h %l %u %t "%r" %s %b'
Combined Log Format :- '%h %l %u %t "%r" %s %b "%{Referrer}i" "%{User-Agent}i"'
Combined Log Format + X-Forwarded-For header :- '%h %l %u %t "%r" %s %b %A %X %T "%{Referer}i" "%{User-Agent}i" X-Forwarded-For="%{X-Forwarded-For}i"'
```

4. Run the following commands to restart Apache Tomcat instance: -

```
systemctl restart tomcat
```

Note:
- Restarting Apache Tomcat does not affect the virtual desktops that are currently running. It will only prevent new users from logging in for the duration of the restart process (typically several seconds).

## Configuration

You need the following information from your `Apache Tomcat instance` to configure this integration in Elastic:

### Apache Tomcat Hostname

Host Configuration Format: `http[s]://<hostname>:<port>/<metrics_path>`

Example Host Configuration: `http://localhost:9090/metrics`

## Validation

After the integration is successfully configured, clicking on the Assets tab of the Apache Tomcat Integration should display a list of available dashboards. Click on the dashboard available for your configured data stream. It should be populated with the required data.

## Troubleshooting

- In case of data ingestion if user encounter following errors then it is because of the rate limit of Prometheus endpoint. Here there won't be any data loss but if user still want to avoid it then make sure configured Prometheus endpoint is not being accessed from multiple places.
```
{
  "error": {
    "message": "unable to decode response from prometheus endpoint: error making http request: Get \"http://127.0.0.1/metrics\": dial tcp 127.0.0.1: connect: connection refused"
  }
}
```

## Logs reference

### Access

This is the `Access` data stream. This data stream collects logs related to overall performance of Java applications.

{{event "access"}}

{{fields "access"}}

### Catalina

This is the `Catalina` data stream. This data stream collects logs related to the startup and shutdown of the Apache Tomcat application server, the deployment of new applications, or the failure of one or more subsystems.

{{event "catalina"}}

{{fields "catalina"}}

### Localhost

This is the `Localhost` data stream. This data stream collects logs related to Web application activity which is related to HTTP transactions between the application server and the client.

{{event "localhost"}}

{{fields "localhost"}}

## Metrics reference

### Cache

This is the `Cache` data stream. This data stream collects metrics related to the size of the cache and time-to-live for cache entries.

{{event "cache"}}

{{fields "cache"}}

### Request

This is the `Request` data stream. This data stream collects metrics related to request count, and amount of data received and sent.

{{event "request"}}

{{fields "request"}}