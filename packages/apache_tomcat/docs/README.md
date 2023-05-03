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
       pattern='%h %l %u %t "%r" %s %b %A %X %T "%{Referer}i" "%{User-Agent}i" X-Forwarded-For="%{X-Forwarded-For}i' />
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

An example event for `access` looks as following:

```json
{
    "@timestamp": "2023-05-02T10:23:04.000Z",
    "agent": {
        "ephemeral_id": "919ea0c0-7f5c-4fc9-b7cf-288a0f913454",
        "id": "41c81fe5-7323-4e84-b501-ddad2fa3530a",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.7.0"
    },
    "apache_tomcat": {
        "access": {
            "http": {
                "ident": "-",
                "useragent": "-"
            }
        }
    },
    "data_stream": {
        "dataset": "apache_tomcat.access",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 11235
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
        "dataset": "apache_tomcat.access",
        "ingested": "2023-05-02T10:23:27Z",
        "kind": "event",
        "module": "apache_tomcat",
        "original": "127.0.0.1 - - [02/May/2023:10:23:04 +0000] \"GET / HTTP/1.1\" 200 11235",
        "outcome": "success",
        "type": [
            "access"
        ]
    },
    "http": {
        "request": {
            "method": "GET"
        },
        "response": {
            "status_code": 200
        },
        "version": "1.1"
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/localhost_access_log.2023-05-02.txt"
        },
        "offset": 0
    },
    "related": {
        "ip": [
            "127.0.0.1"
        ]
    },
    "source": {
        "ip": "127.0.0.1"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "apache_tomcat-access"
    ],
    "url": {
        "original": "/",
        "path": "/"
    }
}
```

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| apache_tomcat.access.connection_status | Connection status when response is completed. | keyword |  |
| apache_tomcat.access.header_forwarder | Header forwarder of log. | ip |  |
| apache_tomcat.access.http.ident | Remote logical username from identd. | keyword |  |
| apache_tomcat.access.http.useragent | The user id of the authenticated user requesting the page (if HTTP authentication is used). | keyword |  |
| apache_tomcat.access.ip.local | Local IP address. | ip |  |
| apache_tomcat.access.response_time | Response time of the endpoint. | double | s |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| input.type | Type of Filebeat input. | keyword |  |
| log.offset | Log offset. | long |  |
| tags | List of keywords used to tag each event. | keyword |  |


### Catalina

This is the `Catalina` data stream. This data stream collects logs related to the startup and shutdown of the Apache Tomcat application server, the deployment of new applications, or the failure of one or more subsystems.

An example event for `catalina` looks as following:

```json
{
    "@timestamp": "2023-05-02T10:24:59.513Z",
    "agent": {
        "ephemeral_id": "9a036955-8538-4820-a80f-09e7a3cec38c",
        "id": "41c81fe5-7323-4e84-b501-ddad2fa3530a",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.7.0"
    },
    "apache_tomcat": {
        "catalina": {
            "subsystem": "main"
        }
    },
    "data_stream": {
        "dataset": "apache_tomcat.catalina",
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
        "dataset": "apache_tomcat.catalina",
        "ingested": "2023-05-02T10:25:52Z",
        "kind": "event",
        "module": "apache_tomcat",
        "original": "02-May-2023 10:24:59.513 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Server version name:   Apache Tomcat/10.1.5",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/catalina.2023-05-02.log"
        },
        "level": "info",
        "offset": 0
    },
    "message": "org.apache.catalina.startup.VersionLoggerListener.log Server version name:   Apache Tomcat/10.1.5",
    "tags": [
        "preserve_original_event",
        "forwarded",
        "apache_tomcat-catalina"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| apache_tomcat.catalina.subsystem | Indicates Tomcat’s subsystem or the type of the module that was the source of the message. For example, RBPM or Java Messaging Service (JMS). | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| tags | List of keywords used to tag each event. | keyword |


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


## Metrics reference

### Cache

This is the `Cache` data stream. This data stream collects metrics related to the size of the cache and time-to-live for cache entries.

An example event for `cache` looks as following:

```json
{
    "@timestamp": "2023-05-02T10:24:35.071Z",
    "agent": {
        "ephemeral_id": "50b70c68-699c-4bb6-9e46-1d19f2f971e1",
        "id": "41c81fe5-7323-4e84-b501-ddad2fa3530a",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.7.0"
    },
    "apache_tomcat": {
        "cache": {
            "application_name": "/",
            "hit": {
                "count": 15
            },
            "lookup": {
                "count": 30
            },
            "object": {
                "size": {
                    "max": {
                        "kb": 512
                    }
                }
            },
            "size": {
                "current": {
                    "kb": 19
                },
                "max": {
                    "kb": 10240
                }
            },
            "ttl": {
                "ms": 5000
            }
        }
    },
    "data_stream": {
        "dataset": "apache_tomcat.cache",
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
        "dataset": "apache_tomcat.cache",
        "duration": 295546716,
        "ingested": "2023-05-02T10:24:39Z",
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
        "apache_tomcat-cache"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |  |
| apache_tomcat.cache.application_name | Name of the Apache Tomcat application. | keyword |  |  |
| apache_tomcat.cache.hit.count | The number of requests for resources that were served from the cache. | double |  | gauge |
| apache_tomcat.cache.lookup.count | The number of requests for resources. | double |  | gauge |
| apache_tomcat.cache.object.size.max.kb | The maximum permitted size for a single object in the cache in kB. | double |  | gauge |
| apache_tomcat.cache.size.current.kb | The current estimate of the cache size in kB. | double |  | gauge |
| apache_tomcat.cache.size.max.kb | The maximum permitted size of the cache in kB. | double |  | gauge |
| apache_tomcat.cache.ttl.ms | The time-to-live for cache entries in milliseconds. | double | ms | gauge |
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
