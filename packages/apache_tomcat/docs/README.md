# Apache Tomcat Integration

## Overview

[Apache Tomcat](https://tomcat.apache.org/tomcat-10.1-doc/logging.html) is a free and open-source implementation of the jakarta servlet, jakarta expression language, and websocket technologies. It provides a pure java http web server environment in which java code can also run. Thus, it is a java web application server, although not a full JEE application server.

Use the Apache Tomcat integration to:

- Collect metrics related to request.
- Create visualizations to monitor, measure and analyze the usage trend and key data, and derive business insights.
- Create alerts to reduce the MTTD and also the MTTR by referencing relevant logs when troubleshooting an issue.

## Data streams

The Apache Tomcat integration collects metrics data.

Metrics give you insight into the statistics of the Apache Tomcat. The `Metric` data stream collected by the Apache Tomcat integration is `request`, so that the user can monitor and troubleshoot the performance of the Apache Tomcat instance.

Data streams:
- `request`: Collects information related to requests of the Apache Tomcat instance.

Note:
- Users can monitor and see the metircs inside the ingested documents for Apache Tomcat in the `metrics-*` index pattern from `Discover`.

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

## Metrics reference

### Request

This is the `Request` data stream. This data stream collects metrics related to request count, and amount of data received and sent.

An example event for `request` looks as following:

```json
{
    "@timestamp": "2023-05-02T10:28:11.414Z",
    "agent": {
        "ephemeral_id": "f49b0637-5820-4155-bed9-519e4db4148a",
        "id": "41c81fe5-7323-4e84-b501-ddad2fa3530a",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.7.0"
    },
    "apache_tomcat": {
        "request": {
            "count": 1,
            "error": {
                "count": 0
            },
            "nio_connector": "http-nio-8080",
            "received": {
                "bytes": 0
            },
            "sent": {
                "bytes": 11215
            },
            "time": {
                "max": 1112,
                "total": 1112
            }
        }
    },
    "data_stream": {
        "dataset": "apache_tomcat.request",
        "namespace": "ep",
        "type": "metrics"
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
        "dataset": "apache_tomcat.request",
        "duration": 317506732,
        "ingested": "2023-05-02T10:28:15Z",
        "kind": "metric",
        "module": "apache_tomcat",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "cdea87653a5e4f29905ca04b74758604",
        "ip": [
            "172.31.0.4"
        ],
        "mac": [
            "02-42-AC-1F-00-04"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.88.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "collector",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service_apache_tomcat_1:9090/metrics",
        "type": "prometheus"
    },
    "tags": [
        "forwarded",
        "apache_tomcat-request"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |  |
| apache_tomcat.request.count | Number of requests processed. | double |  | counter |
| apache_tomcat.request.error.count | Number of errors. | double |  | gauge |
| apache_tomcat.request.nio_connector | Name of NIO Connector. | keyword |  |  |
| apache_tomcat.request.received.bytes | Amount of data received, in bytes. | double | byte | counter |
| apache_tomcat.request.sent.bytes | Amount of data sent, in bytes. | double | byte | counter |
| apache_tomcat.request.time.max | Maximum time(ms) to process a request. | double | ms | counter |
| apache_tomcat.request.time.total | Total time(ms) to process the requests. | double | ms | counter |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.project.id | The cloud project identifier. Examples: Google Cloud Project id, Azure Project id. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |
