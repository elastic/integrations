# MongoDB Atlas Integration

## Overview

[MongoDB Atlas](https://www.mongodb.com/atlas), the leading multi-cloud developer data platform, offers the easiest way to run MongoDB, enabling you to work with your code's objects directly through its document-based data model, which allows for flexible schema and easy scalability.

Use the MongoDB Atlas integration to:

- Collect MongoDB Atlas mongod audit logs, mongod database logs, organization logs, hardware and process metrics for comprehensive monitoring and analysis.
- Create informative visualizations to track usage trends, measure key metrics, and derive actionable business insights.
- Set up alerts to minimize Mean Time to Detect (MTTD) and Mean Time to Resolve (MTTR) by quickly referencing relevant logs during troubleshooting.

## Data streams

The MongoDB Atlas integration collects logs and metrics.

Logs help you keep a record of events that happen on your machine. The `Log` data stream collected by MongoDB Atlas integration are `mongod_audit`, `mongod_database`, and `organization`.

Metrics give you insight into the statistics of the MongoDB Atlas. The `Metric` data stream collected by the MongoDB Atlas integration are `process` and `hardware` so that the user can monitor and troubleshoot the performance of the MongoDB Atlas instance.

Data streams:
- `hardware`: This data stream collects all the Atlas search hardware and status data series within the provided time range for one process in the specified project.
- `mongod_audit`: The auditing facility allows administrators and users to track system activity for deployments with multiple users and applications. Mongod Audit logs capture events related to database operations such as insertions, updates, deletions, user authentication, etc., occurring within the mongod instances.
- `mongod_database`: This data stream collects a running log of events, including entries such as incoming connections, commands run, and issues encountered. Generally, database log messages are useful for diagnosing issues, monitoring your deployment, and tuning performance.
- `organization`: Organization logs provide a detailed view of your organization's activities, enabling tracking and monitoring of significant actions and status changes involving database operations, billing, security, hosts, encryption, user access, and more, as performed by users and teams.
- `process`: This data stream collects host metrics per process for all the hosts of the specified group. Metrics, like measurements for the host such as CPU usage, number of I/O operations, and memory, are available on this data stream.

Note:
- Users can monitor and see the logs and metrics inside the ingested documents for MongoDB Atlas in the `logs-*` index pattern from `Discover`.

## Prerequisites

You can store and search your data using Elasticsearch and visualize and manage it with Kibana. We recommend using our hosted Elasticsearch Service on Elastic Cloud or self-managing the Elastic Stack on your own hardware.

## Setup

### To collect data from MongoDB Atlas, the following parameters from your MongoDB Atlas instance are required

1. Public Key
2. Private Key
3. Group ID
4. Organization ID

### Steps to obtain Public Key, Private Key, Group ID, and Organization ID

1. Generate programmatic API keys with `Organization Owner` permission by following the instructions in the Atlas [documentation](https://www.mongodb.com/docs/atlas/configure-api-access/#grant-programmatic-access-to-an-organization). Then, copy the public and private keys which function as a username and API key respectively.
2. From the Atlas UI with `project owner` permission, go to **Project Settings > Access Manager > API Keys** and then click **Invite To Project** to add the API key created above, as described in the Atlas [documentation](https://www.mongodb.com/docs/atlas/configure-api-access/#invite-an-organization-api-key-to-a-project).
3. Add a specific role to API keys, under **Project Settings > Access Manager > API Keys**. This step is important to make sure that these API keys have the right permissions to access the data without running into any issues. The specific role for each data stream is defined under the data stream reference section.
4. Enable Database Auditing for the Atlas project you want to monitor logs. You can follow the instructions provided in this Atlas [documentation](https://www.mongodb.com/docs/atlas/database-auditing/#procedure).
5. You can find your Project ID (Group ID) in the Atlas UI. To do this, navigate to your project, click on **Settings**, and copy the **Project ID (Group ID)**. You can also programmatically find it using the Atlas Admin API or Atlas CLI as described in this Atlas [documentation](https://www.mongodb.com/docs/atlas/app-services/apps/metadata/#find-a-project-id).
6. On the Atlas UI, select your organization from the context dropdown, click **Settings**, and copy the **Organization ID**.

### Important terms of MongoDB Atlas API

1. Granularity: Duration that specifies the interval at which Atlas reports the metrics.
2. Period: Duration over which Atlas reports the metrics.

Note: Both of the above attributes can be set by using a `period` in configuration parameters.

### Steps to enable Integration in Elastic

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type MongoDB Atlas
3. Click on the "MongoDB Atlas" integration from the search results.
4. To add the integration, click on the "Add MongoDB Atlas" button.
5. Enter all the necessary configuration parameters, including Public Key, Private Key, and GroupId.
6. Finally, save the integration.

Note:
- The `mongod_audit`, `mongod_database`, and `organization` data streams gather historical data spanning the previous 30 minutes.
- We recommend setting an interval of five minutes or higher for collecting mongod audit and database logs, as MongoDB Atlas refreshes logs from the cluster's backend infrastructure at five minutes intervals as described in this Atlas [document](https://www.mongodb.com/docs/atlas/reference/api-resources-spec/v2/#tag/Monitoring-and-Logs/operation/getHostLogs).
- The logs collection from MongoDB Atlas does not support M0 free clusters, M2/M5 shared clusters, or serverless instances.
- Mongod: Mongod is the primary daemon method for the MongoDB system. It helps in handling the data requests, managing the data access, performing background management operations, and other core database operations.

## Troubleshooting

If you encounter an error while ingesting data, it might be due to the data collected over a long time span. Generating a response in such cases may take longer and might cause a request timeout if the `HTTP Client Timeout` parameter is set to a small duration. To avoid this error, it is recommended to adjust the `HTTP Client Timeout` and `Interval` parameters based on the duration of data collection.
```
{
  "error": {
    "message": "failed eval: net/http: request canceled (Client.Timeout or context cancellation while reading body)"
  }
}
```

## Logs reference

### Mongod Audit

This is the `mongod_audit` data stream. This data stream allows administrators and users to track system activity for deployments with multiple users and applications. To collect audit logs, the requesting API Key must have the `Project Data Access Read Only` or higher role.

An example event for `mongod_audit` looks as following:

```json
{
    "@timestamp": "2023-04-01T12:00:00.000Z",
    "agent": {
        "ephemeral_id": "82e5a7ce-c7ad-436f-90f2-a1cefbe22333",
        "id": "498e0c10-4447-4a56-90f0-ba02c44a01c2",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "mongodb_atlas.mongod_audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "498e0c10-4447-4a56-90f0-ba02c44a01c2",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "authenticate",
        "agent_id_status": "verified",
        "category": [
            "network",
            "authentication"
        ],
        "dataset": "mongodb_atlas.mongod_audit",
        "ingested": "2024-04-09T06:13:37Z",
        "kind": "event",
        "module": "mongodb_atlas",
        "type": [
            "access",
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.245.7"
        ],
        "mac": [
            "02-42-C0-A8-F5-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.92.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "cel"
    },
    "mongodb_atlas": {
        "mongod_audit": {
            "hostname": "hostname1",
            "local": {
                "ip": "127.0.0.1",
                "port": 27017
            },
            "remote": {
                "ip": "192.168.1.100",
                "port": 54320
            },
            "result": "Success",
            "user": {
                "names": [
                    {
                        "db": "admin",
                        "user": "auditUser"
                    }
                ],
                "roles": [
                    {
                        "db": "admin",
                        "role": "dbAdmin"
                    }
                ]
            },
            "uuid": {
                "binary": "some-unique-identifier",
                "type": "04"
            }
        }
    },
    "related": {
        "ip": [
            "127.0.0.1",
            "192.168.1.100"
        ]
    },
    "tags": [
        "mongodb_atlas-mongod_audit"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| mongodb_atlas.mongod_audit.hostname | Hostname that stores the log files that you want to download. | keyword |
| mongodb_atlas.mongod_audit.local.ip | IP address of the running instance. | ip |
| mongodb_atlas.mongod_audit.local.is_system_user | True if the event is caused by a system user, false otherwise. | boolean |
| mongodb_atlas.mongod_audit.local.port | Port number of the running instance. | long |
| mongodb_atlas.mongod_audit.local.unix | Unix that contains the MongoDB socket file path if the client connects through a Unix domain socket. | keyword |
| mongodb_atlas.mongod_audit.param | Specific details for the event. | object |
| mongodb_atlas.mongod_audit.remote.ip | IP address of the incoming connection associated with the event. | ip |
| mongodb_atlas.mongod_audit.remote.is_system_user | True if the event is caused by a system user, false otherwise. | boolean |
| mongodb_atlas.mongod_audit.remote.port | Port number of the incoming connection associated with the event. | long |
| mongodb_atlas.mongod_audit.remote.unix | Unix that contains the MongoDB socket file path if the client connects through a Unix domain socket. | keyword |
| mongodb_atlas.mongod_audit.result | Error code. | keyword |
| mongodb_atlas.mongod_audit.user.names | Array of user identification documents. | object |
| mongodb_atlas.mongod_audit.user.roles | Array of documents that specify the roles granted to the user. | object |
| mongodb_atlas.mongod_audit.uuid.binary | Document that contains a universally unique identifier (UUID) for the audit message. | keyword |
| mongodb_atlas.mongod_audit.uuid.type | The $type field specifies the BSON subtype for the $binary field. | keyword |


### Mongod Database

This is the `mongod_database` data stream. This datastream collects a running log of events, including entries such as incoming connections, commands run, monitoring deployment, tuning performance, and issues encountered. To collect database logs, the requesting API Key must have the `Project Data Access Read Only` or higher role.

An example event for `mongod_database` looks as following:

```json
{
    "@timestamp": "2024-02-18T14:45:23.512Z",
    "agent": {
        "ephemeral_id": "dbad1b64-5ae2-467e-a76a-7d31d2bbc35a",
        "id": "35b61223-ca83-481f-a4aa-ab5983a75ba8",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "mongodb_atlas.mongod_database",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "35b61223-ca83-481f-a4aa-ab5983a75ba8",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network",
            "database"
        ],
        "dataset": "mongodb_atlas.mongod_database",
        "ingested": "2024-04-05T10:24:59Z",
        "kind": "event",
        "module": "mongodb_atlas",
        "type": [
            "access",
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.255.7"
        ],
        "mac": [
            "02-42-C0-A8-FF-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.92.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "cel"
    },
    "log": {
        "level": "informational"
    },
    "mongodb_atlas": {
        "mongod_database": {
            "component": "NETWORK",
            "hostname": "hostname1",
            "id": 67890,
            "message": "Client connection accepted",
            "tags": [
                "connection"
            ],
            "thread": {
                "name": "conn123"
            }
        }
    },
    "tags": [
        "mongodb_atlas-mongod_database"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| mongodb_atlas.mongod_database.attributes | One or more key-value pairs for additional log attributes. If a log message does not include any additional attributes, the attr object is omitted. | object |
| mongodb_atlas.mongod_database.component | The component field indicates the category to which a logged event belongs, such as NETWORK or COMMAND. | keyword |
| mongodb_atlas.mongod_database.hostname | A human-readable label that identifies the host that stores the log files you want to download. | keyword |
| mongodb_atlas.mongod_database.id | The unique identifier for the log statement. | long |
| mongodb_atlas.mongod_database.message | The log output message passed from the server or driver. If necessary, the message is escaped according to the JSON specification. | match_only_text |
| mongodb_atlas.mongod_database.size | The original size of a log entry if it has been truncated. Only included if the log entry contains at least one truncated attr attribute. | object |
| mongodb_atlas.mongod_database.tags | Strings representing any tags applicable to the log statement, for example, ["startupWarnings"]. | keyword |
| mongodb_atlas.mongod_database.thread.name | The name of the thread that caused the log statement. | keyword |
| mongodb_atlas.mongod_database.truncated | Information about log message truncation, if applicable. Only included if the log entry contains at least one truncated attr attribute. | object |


### Organization

This is the `organization` data stream. This data stream collects detailed view of your organization's activities, enabling tracking and monitoring of significant actions and status changes involving database operations, billing, security, hosts, encryption, user access, and more, as performed by users and teams.

An example event for `organization` looks as following:

```json
{
    "@timestamp": "2024-04-30T06:17:35.000Z",
    "agent": {
        "ephemeral_id": "1c645786-d85d-402d-ba20-e09c80cec694",
        "id": "15d8bb05-2d3f-4df5-ba3c-2fab23670e47",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "client": {
        "ip": "0.0.0.0"
    },
    "data_stream": {
        "dataset": "mongodb_atlas.organization",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "15d8bb05-2d3f-4df5-ba3c-2fab23670e47",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "configuration",
            "database"
        ],
        "dataset": "mongodb_atlas.organization",
        "id": "66308cff73a61b3c0633ad96",
        "ingested": "2024-05-07T12:23:55Z",
        "kind": "event",
        "module": "mongodb_atlas",
        "type": [
            "info",
            "access",
            "change"
        ]
    },
    "group": {
        "id": "663087fcc4818d301a53af06"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.251.7"
        ],
        "mac": [
            "02-42-C0-A8-FB-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.92.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "cel"
    },
    "mongodb_atlas": {
        "organization": {
            "access_list_entry": "sample.user@example.com",
            "additional_info": {
                "_t": "RESOURCE_AUDIT",
                "cid": "663087fcc4818d301a53af06",
                "cre": "2024-04-30T06:17:35Z",
                "description": "Tag(s) were added or modified on project",
                "gn": "test_project_org",
                "org_name": "Integrations - 2023-05-25",
                "severity": "INFO",
                "source": "USER",
                "tags_added": [
                    "{key=test_123, value=test_123}"
                ],
                "un": "sample1.user@example.com",
                "updated_tags_list": [
                    "{key=application, value=mongo_test}",
                    "{key=test_123, value=test_123}"
                ],
                "ut": "LOCAL"
            },
            "alert": {
                "config": {
                    "id": "sample_alert_config_id"
                },
                "id": "sample_alert_id"
            },
            "api_key": {
                "id": "sample_api_key_id"
            },
            "cluster": {
                "id": "sample_cluster_id",
                "name": "sample_cluster"
            },
            "collection": {
                "name": "sample_collection"
            },
            "current_value": {
                "number": 50,
                "units": "RAW"
            },
            "database": {
                "name": "sample_db"
            },
            "event_type": {
                "name": "GROUP_TAGS_MODIFIED"
            },
            "host": {
                "id": "sample_host_id",
                "name": "sample_hostname"
            },
            "invoice": {
                "id": "sample_invoice_id"
            },
            "is_global_admin": false,
            "metric": {
                "name": "sample_metric"
            },
            "operation": {
                "type": "update"
            },
            "payment": {
                "id": "sample_payment_id"
            },
            "public_key": "sample_public_key",
            "replicaset": {
                "name": "sample_replica_set"
            },
            "shard": {
                "name": "sample_shard"
            },
            "target": {
                "username": "sample.user@example.com"
            },
            "target_public_key": "sample_target_public_key",
            "team": {
                "id": "sample_team_id"
            }
        }
    },
    "organization": {
        "id": "646f418c72f24c07d430aaca"
    },
    "related": {
        "ip": [
            "0.0.0.0"
        ],
        "user": [
            "sample1.user@example.com",
            "sample.user@example.com"
        ]
    },
    "server": {
        "port": 80
    },
    "tags": [
        "mongodb_atlas-organization"
    ],
    "user": {
        "id": "sample_user_id",
        "name": "sample1.user@example.com"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| mongodb_atlas.organization.access_list_entry | Access list entry of the API Key targeted by the event. | keyword |
| mongodb_atlas.organization.additional_info.\* | Additional meta information about the event. Only present when includeRaw query parameter is true. | object |
| mongodb_atlas.organization.alert.config.id | Unique identifier for the alert configuration associated with the alertId. | keyword |
| mongodb_atlas.organization.alert.id | Unique identifier for the alert associated with this event. | keyword |
| mongodb_atlas.organization.api_key.id | Unique identifier for the API Key that triggered this event. | keyword |
| mongodb_atlas.organization.cluster.id | ID of the cluster to which this event applies. | keyword |
| mongodb_atlas.organization.cluster.name | Name of the cluster to which this event applies. | keyword |
| mongodb_atlas.organization.collection.name | Name of the collection where the event occurred. | keyword |
| mongodb_atlas.organization.current_value.number | The value of the metric at the time of the event. | double |
| mongodb_atlas.organization.current_value.units | Relevant units for the value. | keyword |
| mongodb_atlas.organization.database.name | Name of the database where the event occurred. | keyword |
| mongodb_atlas.organization.event_type.name | Name of the event type. | keyword |
| mongodb_atlas.organization.host.id | ID of the host where this event occurred. | keyword |
| mongodb_atlas.organization.host.name | Hostname, FQDN, IPv4 address, or IPv6 address of the host on which this event occurred. | keyword |
| mongodb_atlas.organization.invoice.id | Unique identifier of the invoice associated with this event. | keyword |
| mongodb_atlas.organization.is_global_admin | Flag indicating whether the user who triggered this event is a MongoDB employee. | boolean |
| mongodb_atlas.organization.metric.name | Name of the measurement whose value went outside the threshold. | keyword |
| mongodb_atlas.organization.operation.type | Type of operation that generated the event. | keyword |
| mongodb_atlas.organization.payment.id | Unique identifier of the invoice payment associated with this event. | keyword |
| mongodb_atlas.organization.public_key | Public key associated with the API Key that triggered this event. If this field is present in the response, Cloud Manager does not return the username field. | keyword |
| mongodb_atlas.organization.replicaset.name | Name of the replica set. | keyword |
| mongodb_atlas.organization.shard.name | The name of the shard associated with the event. | keyword |
| mongodb_atlas.organization.target.username | Username for the Cloud Manager user targeted by this event. | keyword |
| mongodb_atlas.organization.target_public_key | Public key of the API Key targeted by the event. | keyword |
| mongodb_atlas.organization.team.id | Unique identifier for the Cloud Manager team associated with this event. | keyword |


## Metrics reference

### Hardware
This data stream collects hardware and status metrics for each process in the specified group. It includes measurements such as CPU usage, memory consumption, JVM memory usage, disk usage, etc.

An example event for `hardware` looks as following:

```json
{
    "@timestamp": "2024-05-08T05:28:35.903Z",
    "agent": {
        "ephemeral_id": "f1da46ba-c948-41e5-8858-28b1db234a9c",
        "id": "130eb953-a957-4fbb-ba6f-5bd31442e2f2",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "mongodb_atlas.hardware",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "130eb953-a957-4fbb-ba6f-5bd31442e2f2",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "mongodb_atlas.hardware",
        "ingested": "2024-05-08T05:28:45Z",
        "kind": "event",
        "module": "mongodb_atlas",
        "type": [
            "access",
            "info"
        ]
    },
    "group": {
        "id": "mongodb-group1"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.253.7"
        ],
        "mac": [
            "02-42-C0-A8-FD-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.114.2.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "cel"
    },
    "mongodb_atlas": {
        "group_id": "mongodb-group1",
        "hardware": {
            "fts": {
                "disk_usage": {
                    "bytes": 175143048.53333333
                }
            },
            "status": {
                "page_faults": 0.16428448420436206
            }
        },
        "process_id": "hostname1"
    },
    "tags": [
        "mongodb_atlas-hardware"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| input.type | Type of Filebeat input. | keyword |  |  |
| mongodb_atlas.group_id | Unique identifier that identifies the project. | keyword |  |  |
| mongodb_atlas.hardware.fts.disk_usage.bytes | Total bytes of disk space that search processes use. | long | byte | gauge |
| mongodb_atlas.hardware.fts.process.cpu.kernel.pct | The amount of CPU time spent by the Full-Text Search process in kernel space. Kernel space includes the core operating system functions such as handling system calls and hardware interrupts. | double | percent | gauge |
| mongodb_atlas.hardware.fts.process.cpu.user.pct | The amount of CPU time spent by the Full-Text Search process in user space. User space includes the execution of application code and processing data | double | percent | gauge |
| mongodb_atlas.hardware.fts.process.memory.resident.bytes | Total bytes of resident memory that search processes occupy. | long | byte | gauge |
| mongodb_atlas.hardware.fts.process.memory.shared.bytes | Total bytes of shared memory that search processes occupy. | long | byte | gauge |
| mongodb_atlas.hardware.fts.process.memory.virtual.bytes | Total bytes of virtual memory that search processes occupy. | long | byte | gauge |
| mongodb_atlas.hardware.fts.process.normalized.cpu.kernel.pct | Percentage of time that the CPU spent servicing operating system calls for the search process. | double | percent | gauge |
| mongodb_atlas.hardware.fts.process.normalized.cpu.user.pct | Percentage of time that the CPU spent servicing user calls for the search process. | double | percent | gauge |
| mongodb_atlas.hardware.status.jvm.memory.heap.available.mb | Total amount of available memory in the JVM heap. | long |  | gauge |
| mongodb_atlas.hardware.status.jvm.memory.heap.used.mb | Amount of memory that the JVM heap is currently using. | long |  | gauge |
| mongodb_atlas.hardware.status.page_faults | Average rate of page faults on this process per second over the selected sample period. | double |  | gauge |
| mongodb_atlas.process_id | Combination of hostname and MongoDB process port that serves the MongoDB process. | keyword |  |  |


### Process
This data stream collects host metrics per process for all the hosts of the specified group. Metrics like measurements for the host, such as CPU usage, number of I/O operations and memory are available on this data stream. To collect process metrics, the requesting API Key must have the `Project Read Only` role.

An example event for `process` looks as following:

```json
{
    "@timestamp": "2024-04-24T13:14:25.586Z",
    "agent": {
        "ephemeral_id": "effbd42a-d55f-49b6-a104-14e765397baf",
        "id": "0e76a408-722e-4fbf-88cf-b53b90679dd9",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "mongodb_atlas.process",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "0e76a408-722e-4fbf-88cf-b53b90679dd9",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "process"
        ],
        "dataset": "mongodb_atlas.process",
        "ingested": "2024-04-24T13:14:35Z",
        "kind": "event",
        "module": "mongodb_atlas",
        "type": [
            "info"
        ]
    },
    "group": {
        "id": "mongodb-group1"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.252.7"
        ],
        "mac": [
            "02-42-C0-A8-FC-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.114.2.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "cel"
    },
    "mongodb_atlas": {
        "group_id": "mongodb-group1",
        "host_id": "hostname1",
        "process": {
            "assert": {
                "regular": 0
            }
        },
        "process_id": "hostname1"
    },
    "tags": [
        "mongodb_atlas-process"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| input.type | Type of Filebeat input. | keyword |  |  |
| mongodb_atlas.group_id | Unique identifier that identifies the project. | keyword |  |  |
| mongodb_atlas.host_id | Unique identifier of the host for the MongoDB process. | keyword |  |  |
| mongodb_atlas.process.assert.msg | The average rate of message asserts per second over the selected sample period. | double |  | gauge |
| mongodb_atlas.process.assert.regular | The average rate of regular asserts raised per second over the selected sample period. | double |  | gauge |
| mongodb_atlas.process.assert.user | The average rate of user asserts per second over the selected sample period. | double |  | gauge |
| mongodb_atlas.process.assert.warning | The average rate of warnings per second over the selected sample period. | double |  | gauge |
| mongodb_atlas.process.background_flush.avg | Amount of data flushed in the background. | double |  | gauge |
| mongodb_atlas.process.cache.dirty.bytes | Amount of dirty bytes in the WiredTiger storage engine cache. | double | byte | gauge |
| mongodb_atlas.process.cache.read.bytes | Read - Amount of bytes in the WiredTiger storage engine cache. | double | byte | gauge |
| mongodb_atlas.process.cache.used.total.bytes | Amount of used bytes in the WiredTiger storage engine cache. | double | byte | gauge |
| mongodb_atlas.process.cache.write.bytes | Write - Amount of bytes in the WiredTiger storage engine cache. | double | byte | gauge |
| mongodb_atlas.process.connections | Displays the total number of active connections to the database deployment. Monitor connections to determine whether the current connection limits are sufficient. | double |  | gauge |
| mongodb_atlas.process.cpu.children.kernel.max.pct | The maximum amount of CPU time spent by child processes in kernel space. | double | percent | counter |
| mongodb_atlas.process.cpu.children.kernel.pct | CPU children kernel space for mongodb processes. | double | percent | gauge |
| mongodb_atlas.process.cpu.children.user.max.pct | The maximum amount of CPU time spent by child processes in user space. | double | percent | counter |
| mongodb_atlas.process.cpu.children.user.pct | CPU children user space for mongodb. | double | percent | gauge |
| mongodb_atlas.process.cpu.kernel.max.pct | The maximum amount of CPU time spent by the MongoDB process itself in kernel space, handling system calls and hardware interrupts. | double | percent | counter |
| mongodb_atlas.process.cpu.kernel.pct | CPU kernel space for mongodb processes. | double | percent | gauge |
| mongodb_atlas.process.cpu.normalized.children.kernel.max.pct | Max children kernel CPU usage scaled to a range of 0% to 100%, is obtained by dividing the usage value by the total number of CPU cores. | double | percent | counter |
| mongodb_atlas.process.cpu.normalized.children.kernel.pct | NORMALIZED CPU children kernel space for mongodb processes. | double | percent | gauge |
| mongodb_atlas.process.cpu.normalized.children.user.max.pct | Max children user CPU usage scaled to a range of 0% to 100%, is obtained by dividing the usage value by the total number of CPU cores. | double | percent | counter |
| mongodb_atlas.process.cpu.normalized.children.user.pct | NORMALIZED CPU children user space for mongodb. | double | percent | gauge |
| mongodb_atlas.process.cpu.normalized.kernel.max.pct | Max kernel CPU usage scaled to a range of 0% to 100%, is obtained by dividing the usage value by the total number of CPU cores. | double | percent | counter |
| mongodb_atlas.process.cpu.normalized.kernel.pct | NORMALIZED CPU kernel space for mongodb processes. | double | percent | gauge |
| mongodb_atlas.process.cpu.normalized.user.max.pct | Max user CPU usage scaled to a range of 0% to 100%, is obtained by dividing the usage value by the total number of CPU cores. | double | percent | counter |
| mongodb_atlas.process.cpu.normalized.user.pct | NORMALIZED CPU user space for mongodb processes. | double | percent | gauge |
| mongodb_atlas.process.cpu.user.max.pct | The maximum amount of CPU time spent by the MongoDB process itself in user space, executing application code and processing data. | double | percent | counter |
| mongodb_atlas.process.cpu.user.pct | CPU user space for mongodb processes. | double | percent | gauge |
| mongodb_atlas.process.cursor.open.total | The number of cursors that the server maintains for clients. | long |  | gauge |
| mongodb_atlas.process.cursor.timed_out.total | The average rate of cursors that have timed out per second over the selected sample period. | double |  | gauge |
| mongodb_atlas.process.database.size.total.bytes | The amount of storage space in bytes that your stored data uses. | long | byte | gauge |
| mongodb_atlas.process.database.storage.total.bytes | Sum total of the compressed on-disk storage space allocated for document storage across all databases. | long | byte | gauge |
| mongodb_atlas.process.document.deleted | Displays the documents deleted per second. | double |  | gauge |
| mongodb_atlas.process.document.inserted | Displays the documents inserted per second. | double |  | gauge |
| mongodb_atlas.process.document.returned | Displays the documents returned per second. | double |  | gauge |
| mongodb_atlas.process.document.updated | Displays the documents updated per second. | double |  | gauge |
| mongodb_atlas.process.fts.cpu.kernel.pct | The amount of CPU time spent by the Full-Text search process in kernel space. | double | percent | gauge |
| mongodb_atlas.process.fts.cpu.normalized.kernel.pct | Percentage of time that the CPU spent servicing the operating system calls for the search process. | double | percent | gauge |
| mongodb_atlas.process.fts.cpu.normalized.user.pct | Percentage of time that the CPU spent servicing user calls for the search process. | double | percent | gauge |
| mongodb_atlas.process.fts.cpu.user.pct | The amount of CPU time spent by the Full-Text search process in user space. | double | percent | gauge |
| mongodb_atlas.process.fts.disk.utilization.total.bytes | Total bytes of disk space that search processes use. | long | byte | gauge |
| mongodb_atlas.process.fts.memory.mapped.total.bytes | Total bytes of mapped memory that search processes occupy. | long | byte | gauge |
| mongodb_atlas.process.fts.memory.resident.total.bytes | Total bytes of resident memory that search processes occupy. | long | byte | gauge |
| mongodb_atlas.process.fts.memory.virtual.total.bytes | Total bytes of virtual memory that search processes occupy. | long | byte | gauge |
| mongodb_atlas.process.global.access.not_in_memory | The number of accesses to data that are not currently stored in memory, requiring disk access. | long |  | gauge |
| mongodb_atlas.process.global.lock.current_queue.reader.count | The number of operations that are currently queued and waiting for the read lock. | long |  | gauge |
| mongodb_atlas.process.global.lock.current_queue.total | The total number of operations queued waiting for the lock (readers + writers) | long |  | gauge |
| mongodb_atlas.process.global.lock.current_queue.writer.count | The number of operations that are currently queued and waiting for the write lock. | long |  | gauge |
| mongodb_atlas.process.global.page_fault.exception_thrown | The number of exceptions thrown due to page faults. | long |  | gauge |
| mongodb_atlas.process.host.page_faults | Measurements on page faults related to the host. | double |  | gauge |
| mongodb_atlas.process.index.btree.access.count | Number of index btree ACCESSES. | long |  | gauge |
| mongodb_atlas.process.index.btree.hits.count | Number of index btree HITS. | long |  | gauge |
| mongodb_atlas.process.index.btree.miss.count | Number of index btree MISSES. | long |  | gauge |
| mongodb_atlas.process.index.btree.miss_ratio.count | Index btree miss ratio. | double |  | gauge |
| mongodb_atlas.process.journaling.commits.write_lock | Number of journaling COMMIT operations. | long |  | gauge |
| mongodb_atlas.process.journaling.mb | Average amount of data in megabytes Cloud Manager writes to the recovery log per second meets your specified threshold. | double |  | gauge |
| mongodb_atlas.process.journaling.write.data_files.mb | The maximum size in megabytes (MB) of data files written by the journaling process. | double |  | gauge |
| mongodb_atlas.process.memory.computed.mb | Amount of COMPUTED process memory in megabytes. | double |  | gauge |
| mongodb_atlas.process.memory.mapped.mb | Amount of MAPPED process memory in megabytes. | double |  | gauge |
| mongodb_atlas.process.memory.resident.mb | Amount of RESIDENT process memory in megabytes. | double |  | gauge |
| mongodb_atlas.process.memory.virtual.mb | Amount of VIRTUAL process memory in megabytes. | double |  | gauge |
| mongodb_atlas.process.network.in | Process incoming network throughput in bytes per second. | double |  | gauge |
| mongodb_atlas.process.network.out | Process outgoing network throughput in bytes per second. | double |  | gauge |
| mongodb_atlas.process.network.request.total | The total number of distinct requests that the process has received. | double |  | counter |
| mongodb_atlas.process.opcounter.cmd | Database operations rate on a process since the process last started. | double |  | gauge |
| mongodb_atlas.process.opcounter.delete | Database DELETE operations rate on a process since the process last started. | double |  | gauge |
| mongodb_atlas.process.opcounter.getmore | Database GETMORE operations rate on a process since the process last started. | double |  | gauge |
| mongodb_atlas.process.opcounter.insert | Database INSERT operations rate on a process since the process last started. | double |  | gauge |
| mongodb_atlas.process.opcounter.query | Database QUERY operations rate on a process since the process last started. | double |  | gauge |
| mongodb_atlas.process.opcounter.repl.cmd | Database operations rate on secondaries. | double |  | gauge |
| mongodb_atlas.process.opcounter.repl.delete | Database DELETE operations rate on secondaries. | double |  | gauge |
| mongodb_atlas.process.opcounter.repl.insert | Database INSERT operations rate on secondaries. | double |  | gauge |
| mongodb_atlas.process.opcounter.repl.update | Database UPDATE operations rate on secondaries. | double |  | gauge |
| mongodb_atlas.process.opcounter.update | Database UPDATE operations rate on a process since the process last started. | double |  | gauge |
| mongodb_atlas.process.operation.execution.time.cmd.avg.ms | Average execution time in milliseconds per command operation over the selected sample period. | double | ms | gauge |
| mongodb_atlas.process.operation.execution.time.read.avg.ms | Average execution time in milliseconds per read operation over the selected sample period. | double | ms | gauge |
| mongodb_atlas.process.operation.execution.time.write.avg.ms | Average execution time in milliseconds per write operation over the selected sample period. | double | ms | gauge |
| mongodb_atlas.process.operation.scan_and_order | The total number of queries that return sorted data that cannot perform the sort operation using an index. | double |  | gauge |
| mongodb_atlas.process.oplog.master.lag.time_diff.s | Lag or delay in replication between the primary node (oplog master) and its secondary nodes. | double | s | gauge |
| mongodb_atlas.process.oplog.master.time.s | The replication oplog window. The approximate time available in the primary's replication oplog. If a secondary is behind real-time by more than this amount, it cannot catch up and will require a full resync. | double | s | gauge |
| mongodb_atlas.process.oplog.rate.gb_per_hour | The rate of change in the size of the oplog in gigabytes per hour. | double |  | gauge |
| mongodb_atlas.process.oplog.repl_lag.s | The amount of time, typically in seconds, it takes for changes recorded in the oplog on the primary node to be replicated and applied to the secondary node. | double | s | gauge |
| mongodb_atlas.process.oplog.slave.lag.master.time.s | The difference in time, typically in seconds, between the oplog time on the secondary (slave) node and the time of the latest operation in the oplog on the primary (master) node. | double | s | gauge |
| mongodb_atlas.process.query.executor.scanned | Average rate per second to scan index items during queries and query-plan evaluations. | double |  | gauge |
| mongodb_atlas.process.query.executor.scanned_objects | Average rate of documents scanned per second during queries and query-plan evaluations. | double |  | gauge |
| mongodb_atlas.process.query.targeting.scanned_objects_per_returned | Ratio of the number of documents scanned to the number of documents returned. | double |  | gauge |
| mongodb_atlas.process.query.targeting.scanned_per_returned | Ratio of the number of index items scanned to the number of documents returned. | double |  | gauge |
| mongodb_atlas.process.restart.in_last_hour | Number of times the host restarted within the previous hour. | double |  | gauge |
| mongodb_atlas.process.swap.usage.free.max.kb | Max amount of swap space free. | double |  | counter |
| mongodb_atlas.process.swap.usage.total.free | Total amount of swap space free. | double |  | gauge |
| mongodb_atlas.process.swap.usage.total.used | Total amount of swap space in use. | double |  | gauge |
| mongodb_atlas.process.swap.usage.used.max.kb | Max amount of swap space in use. | double |  | counter |
| mongodb_atlas.process.system.cpu.guest.max.pct | Max amount of CPU time spent running a virtual CPU for guest operating systems. | double | percent | counter |
| mongodb_atlas.process.system.cpu.guest.pct | Tracks CPU time consumed by guest operating systems, like virtual machines, on the host system. | double | percent | gauge |
| mongodb_atlas.process.system.cpu.iowait.max.pct | Max amount of CPU time spent waiting for I/O operations to complete. | double | percent | counter |
| mongodb_atlas.process.system.cpu.iowait.pct | The CPU time spent waiting for I/O operations to complete. | double | percent | gauge |
| mongodb_atlas.process.system.cpu.irq.max.pct | Max amount of CPU time spent servicing hardware interrupts. | double | percent | counter |
| mongodb_atlas.process.system.cpu.irq.pct | The portion of CPU time spent servicing hardware interrupts. | double | percent | gauge |
| mongodb_atlas.process.system.cpu.kernel.max.pct | Max amount of CPU time spent in kernel space, executing system calls and handling hardware interrupts. | double | percent | counter |
| mongodb_atlas.process.system.cpu.kernel.pct | The portion of CPU time spent executing kernel space processes and handling system calls. | double | percent | gauge |
| mongodb_atlas.process.system.cpu.nice.pct | The portion of CPU time allocated to processes with a 'nice' priority level. | double | percent | gauge |
| mongodb_atlas.process.system.cpu.softirq.max.pct | Max amount of CPU time spent servicing soft interrupts, which are interrupts triggered by software. | double | percent | counter |
| mongodb_atlas.process.system.cpu.softirq.pct | The CPU time spent handling software-generated interrupts. | double | percent | gauge |
| mongodb_atlas.process.system.cpu.steal.max.pct | Max amount of CPU time 'stolen' by the hypervisor for other virtual machines running on the same physical host. | double | percent | counter |
| mongodb_atlas.process.system.cpu.steal.pct | The amount of CPU time 'stolen' by the hypervisor for other virtual machines running on the same physical host. | double | percent | gauge |
| mongodb_atlas.process.system.cpu.user.max.pct | Max amount of CPU time spent in user space, executing user-level processes and applications. | double | percent | counter |
| mongodb_atlas.process.system.cpu.user.pct | The portion of CPU time spent executing user space processes and running applications. | double | percent | gauge |
| mongodb_atlas.process.system.memory.available.kb | Physical memory available in kilobytes. | double |  | gauge |
| mongodb_atlas.process.system.memory.available.max.kb | Max Physical memory available in kilobytes. | double |  | counter |
| mongodb_atlas.process.system.memory.free.kb | Physical memory free in kilobytes. | double |  | gauge |
| mongodb_atlas.process.system.memory.free.max.kb | Max Physical memory free in kilobytes. | double |  | counter |
| mongodb_atlas.process.system.memory.used.kb | Physical memory used in kilobytes. | double |  | gauge |
| mongodb_atlas.process.system.memory.used.max.kb | Max Physical memory used in kilobytes. | double |  | counter |
| mongodb_atlas.process.system.network.in | Incoming network throughput in bytes per second. | double |  | gauge |
| mongodb_atlas.process.system.network.max.in | Max Incoming network throughput in bytes per second. | double |  | counter |
| mongodb_atlas.process.system.network.max.out | Max Outgoing network throughput in bytes per second. | double |  | counter |
| mongodb_atlas.process.system.network.out | Outgoing network throughput in bytes per second. | double |  | gauge |
| mongodb_atlas.process.system.normalized.cpu.guest.max.pct | Max Guest CPU usage of processes on the host scaled to a range of 0 to 100%, is obtained by dividing the usage value by the total number of CPU cores. | double | percent | counter |
| mongodb_atlas.process.system.normalized.cpu.guest.pct | Guest CPU usage of processes on the host scaled to a range of 0 to 100%, is obtained by dividing the usage value by the total number of CPU cores. | double | percent | gauge |
| mongodb_atlas.process.system.normalized.cpu.iowait.max.pct | Max CPU usage of processes spent waiting for IO operations to complete, scaled to a range of 0 to 100%, is obtained by dividing the usage value by the total number of CPU cores. | double | percent | counter |
| mongodb_atlas.process.system.normalized.cpu.iowait.pct | CPU usage of processes spent waiting for IO operations to complete, scaled to a range of 0 to 100%, is obtained by dividing the usage value by the total number of CPU cores. | double | percent | gauge |
| mongodb_atlas.process.system.normalized.cpu.irq.max.pct | Max CPU usage of hardware interrupts, scaled to a range of 0 to 100%, is obtained by dividing the usage value by the total number of CPU cores. | double | percent | counter |
| mongodb_atlas.process.system.normalized.cpu.irq.pct | NORMALIZED irq CPU utilization across various processes for a server | double | percent | gauge |
| mongodb_atlas.process.system.normalized.cpu.kernel.max.pct | Max kernel CPU usage of processes on the host scaled to a range of 0 to 100%, is obtained by dividing the usage value by the total number of CPU cores. | double | percent | counter |
| mongodb_atlas.process.system.normalized.cpu.kernel.pct | Kernel CPU usage of processes on the host scaled to a range of 0 to 100%, is obtained by dividing the usage value by the total number of CPU cores. | double | percent | gauge |
| mongodb_atlas.process.system.normalized.cpu.nice.max.pct | Max CPU usage of processes with a positive nice value, scaled to a range of 0 to 100%, is obtained by dividing the usage value by the total number of CPU cores. | double | percent | counter |
| mongodb_atlas.process.system.normalized.cpu.nice.pct | NORMALIZED nice CPU utilization across various processes for a server | double | percent | gauge |
| mongodb_atlas.process.system.normalized.cpu.softirq.max.pct | Max CPU usage of software interrupts, scaled to a range of 0 to 100%, is obtained by dividing the usage value by the total number of CPU cores. | double | percent | counter |
| mongodb_atlas.process.system.normalized.cpu.softirq.pct | NORMALIZED softirq CPU utilization across various processes for a server | double | percent | gauge |
| mongodb_atlas.process.system.normalized.cpu.steal.max.pct | Max The percentage of time the CPU had something runnable, but the hypervisor chose to run something else, scaled to a range of 0 to 100%, is obtained by dividing the usage value by the total number of CPU cores. | double | percent | counter |
| mongodb_atlas.process.system.normalized.cpu.steal.pct | The percentage of time the CPU had something runnable, but the hypervisor chose to run something else, scaled to a range of 0 to 100%, is obtained by dividing the usage value by the total number of CPU cores. | double | percent | gauge |
| mongodb_atlas.process.system.normalized.cpu.steal.user.max.pct | Max user CPU usage of processes on the host scaled to a range of 0 to 100%, is obtained by dividing the usage value by the total number of CPU cores. | double | percent | counter |
| mongodb_atlas.process.system.normalized.cpu.steal.user.pct | NORMALIZED CPU user space utilization across various processes for a server | double | percent | gauge |
| mongodb_atlas.process.system.normalized.cpu.user.max.pct | Max user CPU usage of processes on the host scaled to a range of 0 to 100%, is obtained by dividing the usage value by the total number of CPU cores. | double | percent | counter |
| mongodb_atlas.process.system.normalized.cpu.user.pct | The portion of CPU time spent executing user space processes and running applications. | double | percent | gauge |
| mongodb_atlas.process.ticket.available.read.count | The number of read tickets available to the WiredTiger storage engine. | long |  | gauge |
| mongodb_atlas.process.ticket.available.write.count | The number of write tickets available to the WiredTiger storage engine. | long |  | gauge |
| mongodb_atlas.process_id | Combination of hostname and MongoDB process port that serves the MongoDB process. | keyword |  |  |
