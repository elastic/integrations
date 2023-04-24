# Tomcat Integration

## Overview

[Apache Tomcat](https://tomcat.apache.org/tomcat-10.1-doc/logging.html) is a free and open-source implementation of the jakarta servlet, jakarta expression language, and websocket technologies. It provides a pure java http web server environment in which java code can also run. Thus, it is a java web application server, although not a full JEE application server.

Use the Tomcat integration to:

- Collect collect logs related to localhost.
- Create visualizations to monitor, measure and analyze the usage trend and key data, and derive business insights.
- Create alerts to reduce the MTTD and also the MTTR by referencing relevant logs when troubleshooting an issue.

## Data streams

The Tomcat integration collects logs data.

Logs help you keep a record of events that happen on your machine. The `Log` data streams collected by Tomcat integration are `localhost`, and `log`, so that users could monitor and troubleshoot the performance of Java applications.

Data streams:
- `localhost`: Collects information related to Web application activity which is related to HTTP transactions between the application server and the client.
- `log` (Deprecated) : supports Apache Tomcat logs.

Note:
- Users can monitor and see the log inside the ingested documents for Tomcat in the `logs-*` index pattern from `Discover`.

## Compatibility

This integration has been tested against Tomcat versions `10.1.5`, `9.0.71` and `8.5.85`.

In order to find out the Tomcat version of instance, see following approaches:

1. Go to Tomcat web instance and on top left corner user can see `Apache Tomcat/10.1.5`. Here `10.1.5` is Tomcat version.

2. Go to `<tomcat_home>/bin` in CLI. Please run the following command:

```
sh version.sh
```

## Prerequisites

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your own hardware.

## Validation

After the integration is successfully configured, clicking on the Assets tab of the Tomcat Integration should display a list of available dashboards. Click on the dashboard available for your configured data stream. It should be populated with the required data.

## Logs reference

### Localhost

This is the `Localhost` data stream. This data stream collects logs related to Web application activity which is related to HTTP transactions between the application server and the client.

{{event "localhost"}}

{{fields "localhost"}}

### Log (Deprecated)

The `log` dataset collects Apache Tomcat logs. This data stream is deprecated and will be removed soon.

{{fields "log"}}
