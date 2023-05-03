# Apache Tomcat Integration

## Overview

[Apache Tomcat](https://tomcat.apache.org/tomcat-10.1-doc/logging.html) is a free and open-source implementation of the jakarta servlet, jakarta expression language, and websocket technologies. It provides a pure java http web server environment in which java code can also run. Thus, it is a java web application server, although not a full JEE application server.

Use the Apache Tomcat integration to:

- Collect logs related to localhost.
- Create visualizations to monitor, measure and analyze the usage trend and key data, and derive business insights.
- Create alerts to reduce the MTTD and also the MTTR by referencing relevant logs when troubleshooting an issue.

## Data streams

The Apache Tomcat integration collects logs data.

Logs help you keep a record of events that happen on your machine. The `Log` data stream collected by Apache Tomcat integration is `localhost`, so that users could monitor and troubleshoot the performance of Java applications.

Data streams:
- `localhost`: Collects information related to Web application activity which is related to HTTP transactions between the application server and the client.

Note:
- Users can monitor and see the log inside the ingested documents for Apache Tomcat in the `logs-*` index pattern from `Discover`.

## Compatibility

This integration has been tested against Apache Tomcat versions `10.1.5`, `9.0.71` and `8.5.85`.

## Prerequisites

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your own hardware.

## Validation

After the integration is successfully configured, clicking on the Assets tab of the Apache Tomcat Integration should display a list of available dashboards. Click on the dashboard available for your configured data stream. It should be populated with the required data.

## Logs reference

### Localhost

This is the `Localhost` data stream. This data stream collects logs related to Web application activity which is related to HTTP transactions between the application server and the client.

An example event for `localhost` looks as following:

```json
{
    "@timestamp": "2023-02-23T15:40:03.711Z",
    "agent": {
        "ephemeral_id": "e926b42c-fc1c-4eb4-85d2-3bb7debc0a79",
        "id": "41c81fe5-7323-4e84-b501-ddad2fa3530a",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.7.0"
    },
    "apache_tomcat": {
        "localhost": {
            "subsystem": "localhost-startStop-1"
        }
    },
    "data_stream": {
        "dataset": "apache_tomcat.localhost",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.7.0"
    },
    "elastic_agent": {
        "id": "41c81fe5-7323-4e84-b501-ddad2fa3530a",
        "snapshot": false,
        "version": "8.7.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "apache_tomcat.localhost",
        "ingested": "2023-05-02T10:27:05Z",
        "kind": "event",
        "module": "apache_tomcat",
        "original": "23-Feb-2023 15:40:03.711 INFO [localhost-startStop-1] org.apache.catalina.core.ApplicationContext.log ContextListener: contextInitialized()",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/localhost.log"
        },
        "level": "info",
        "offset": 0
    },
    "message": "org.apache.catalina.core.ApplicationContext.log ContextListener: contextInitialized()",
    "tags": [
        "preserve_original_event",
        "forwarded",
        "apache_tomcat-localhost"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| apache_tomcat.localhost.subsystem | Indicates Tomcat’s subsystem or the type of the module that was the source of the message. For example, RBPM or Java Messaging Service (JMS). | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| tags | List of keywords used to tag each event. | keyword |

