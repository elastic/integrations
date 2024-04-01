# MongoDB Atlas Integration

## Overview

[MongoDB Atlas](https://www.mongodb.com/atlas) is a multi-cloud developer data platform. At its core is our fully managed cloud database for modern applications. Atlas is the best way to run MongoDB, the leading non-relational database. MongoDB’s document model is the fastest way to innovate because documents map directly to the objects in your code. As a result, they are much easier and more natural to work with. You can store data of any structure and modify your schema at any time as you add new features to your applications.

Use the MongoDB Atlas integration to:

- Collect Mongod Audit logs.
- Create visualizations to monitor, measure and analyze the usage trend and key data, and derive business insights.
- Create alerts to reduce the MTTD and also the MTTR by referencing relevant logs when troubleshooting an issue.

## Data streams

The MongoDB Atlas integration collects logs.

Logs help you keep a record of events that happen on your machine. The `Log` data stream collected by MongoDB Atlas integration is `mongod_audit`.

Data streams:
- `mongod_audit`: The auditing facility allows administrators and users to track system activity for deployments with multiple users and applications. Mongod Audit logs capture events related to database operations such as insertions, updates, deletions, user authentication, etc., occurring within the mongod instances.

Note:
- Users can monitor and see the log inside the ingested documents for MongoDB Atlas in the `logs-*` index pattern from `Discover`.

## Prerequisites

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. 
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your own hardware.

## Setup

### To collect data from MongoDB Atlas, the following parameters from your MongoDB Atlas instance are required:

1. Public Key
2. Private Key
3. GroupId

### Steps to obtain Public Key, Private Key and GroupId:

1. Generate programmatic API Keys with project owner permissions using the instructions in the Atlas [documentation](https://www.mongodb.com/docs/atlas/configure-api-access/#create-an-api-key-for-a-project). Then, copy the public key and private key. These serve the same function as a username and API Key respectively.
2. Enable Database Auditing for the Atlas project for which you want to monitor logs, as described in this Atlas [document](https://www.mongodb.com/docs/atlas/database-auditing/#procedure).
3. You can find your GroupId(ProjectID) in the Atlas UI. Go to your project, click Settings, and copy the GroupID(ProjectID). You can use the Atlas Admin API or Atlas CLI to find it programmatically. As described in this Atlas [document](https://www.mongodb.com/docs/atlas/app-services/apps/metadata/#find-a-project-id)

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type MongoDB Atlas
3. Click on the "MongoDB Atlas" integration from the search results.
4. Click on the "Add MongoDB Atlas" button to add the integration.
5. Add all the required integration configuration parameters, such as Public Key, Private Key, URL and GroupId. For Mongod Audit data stream.
6. Save the integration.

Note:
- The `mongod_audit` data stream gathers historical data spanning the previous 30 minutes.
- Mongod: Mongod is the primary daemon method for the MongoDB system. It helps in handling the data requests, managing the data access, performing background management operations, and other core database operations.

## Troubleshooting

- If the user encounters the following error during data ingestion, it is likely due to the data collected through this endpoint covers a long time span. As a result, generating a response may take longer. Additionally, if the `HTTP Client Timeout` parameter is set to a small duration,  a request timeout might happen. However, if the user wishes to avoid this error altogether, it is recommended to adjust the `HTTP Client Timeout` and `Interval` parameters based on the duration of data collection.
```
{
  "error": {
    "message": "failed eval: net/http: request canceled (Client.Timeout or context cancellation while reading body)"
  }
}
```

## Logs reference

### Mongod Audit

This is the `mongod_audit` data stream. This data stream allows administrators and users to track system activity for deployments with multiple users and applications.

An example event for `mongod_audit` looks as following:

```json
{
    "@timestamp": "2023-04-01T12:00:00.000Z",
    "agent": {
        "ephemeral_id": "d3ebc4ac-0cb3-41a2-90b2-cbd7055d60b8",
        "id": "6baea824-3495-4407-aac0-d9a0cb99c4f8",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.0"
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
        "id": "6baea824-3495-4407-aac0-d9a0cb99c4f8",
        "snapshot": false,
        "version": "8.12.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network",
            "authentication"
        ],
        "dataset": "mongodb_atlas.mongod_audit",
        "ingested": "2024-04-01T09:36:02Z",
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
        "id": "829324aac17946dcace17006fa82a2d2",
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
    "mongodb_atlas": {
        "mongod_audit": {
            "action": {
                "type": "authenticate"
            },
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| input.type | Type of Filebeat input. | keyword |
| mongodb_atlas.mongod_audit.action.type | Action type of Audit Event. | keyword |
| mongodb_atlas.mongod_audit.hostname | Human-readable label that identifies the host that stores the log files that you want to download. | keyword |
| mongodb_atlas.mongod_audit.local.ip | A document that contains the IP address of the running instance. | ip |
| mongodb_atlas.mongod_audit.local.is_system_user | This field indicates whether the user who caused the event was a system user. | boolean |
| mongodb_atlas.mongod_audit.local.port | A document that contains the port number of the running instance. | long |
| mongodb_atlas.mongod_audit.local.unix | Unix that contains the MongoDB socket file path if the client connects through a Unix domain socket. | keyword |
| mongodb_atlas.mongod_audit.param | Specific details for the event. | object |
| mongodb_atlas.mongod_audit.remote.ip | A document that contains the IP address of the incoming connection associated with the event. | ip |
| mongodb_atlas.mongod_audit.remote.is_system_user | This field indicates whether the user who caused the event was a system user. | boolean |
| mongodb_atlas.mongod_audit.remote.port | A document that contains the port number of the incoming connection associated with the event. | long |
| mongodb_atlas.mongod_audit.remote.unix | Unix that contains the MongoDB socket file path if the client connects through a Unix domain socket. | keyword |
| mongodb_atlas.mongod_audit.result | Error code. | keyword |
| mongodb_atlas.mongod_audit.user.names | Array of user identification documents. | object |
| mongodb_atlas.mongod_audit.user.roles | Array of documents that specify the roles granted to the user. | object |
| mongodb_atlas.mongod_audit.uuid.binary | Document that contains a universally unique identifier (UUID) for the audit message. | keyword |
| mongodb_atlas.mongod_audit.uuid.type | The $type field specifies the BSON subtype for the $binary field. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| tags | List of keywords used to tag each event. | keyword |
