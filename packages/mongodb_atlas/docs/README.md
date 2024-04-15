# MongoDB Atlas Integration

## Overview

[MongoDB Atlas](https://www.mongodb.com/atlas), the leading multi-cloud developer data platform, offers the easiest way to run MongoDB, enabling you to work with your code's objects directly through its document-based data model, which allows for flexible schema and easy scalability.

Use the MongoDB Atlas integration to:

- Collect MongoDB Audit logs for comprehensive monitoring and analysis.
- Create informative visualizations to track usage trends, measure key metrics, and derive actionable business insights.
- Set up alerts to minimize Mean Time to Detect (MTTD) and Mean Time to Resolve (MTTR) by quickly referencing relevant logs during troubleshooting.

## Data streams

The MongoDB Atlas integration collects logs.

Logs help you keep a record of events that happen on your machine. The `Log` data stream collected by MongoDB Atlas integration is `mongod_audit`.

Data streams:
- `mongod_audit`: The auditing facility allows administrators and users to track system activity for deployments with multiple users and applications. Mongod Audit logs capture events related to database operations such as insertions, updates, deletions, user authentication, etc., occurring within the mongod instances.

Note:
- Users can monitor and see the log inside the ingested documents for MongoDB Atlas in the `logs-*` index pattern from `Discover`.

## Prerequisites

You can store and search your data using Elasticsearch and visualize and manage it with Kibana. We recommend using our hosted Elasticsearch Service on Elastic Cloud or self-managing the Elastic Stack on your own hardware.

## Setup

### To collect data from MongoDB Atlas, the following parameters from your MongoDB Atlas instance are required:

1. Public Key
2. Private Key
3. GroupId

### Steps to obtain Public Key, Private Key and GroupId:

1. Generate programmatic API Keys with project owner permissions using the instructions in the Atlas [documentation](https://www.mongodb.com/docs/atlas/configure-api-access/#create-an-api-key-for-a-project). Then, copy the public key and private key. These serve the same function as a username and API Key respectively.
2. Enable Database Auditing for the Atlas project you want to monitor logs. You can follow the instructions provided in this Atlas [document](https://www.mongodb.com/docs/atlas/database-auditing/#procedure).
3. You can find your Project ID (Group ID) in the Atlas UI. To do this, navigate to your project, click on Settings, and copy the Project ID (Group ID). You can also programmatically find it using the Atlas Admin API or Atlas CLI as described in this Atlas [document](https://www.mongodb.com/docs/atlas/app-services/apps/metadata/#find-a-project-id).

### Steps to enable Integration in Elastic

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type MongoDB Atlas
3. Click on the "MongoDB Atlas" integration from the search results.
4. To add the integration, click on the "Add MongoDB Atlas" button.
5. Enter all the necessary configuration parameters, including Public Key, Private Key, and GroupId.
6. Finally, save the integration.

Note:
- The `mongod_audit` data stream gathers historical data spanning the previous 30 minutes.
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

This is the `mongod_audit` data stream. This data stream allows administrators and users to track system activity for deployments with multiple users and applications.

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
| mongodb_atlas.mongod_audit.local.is_system_user | This field indicates whether the user who caused the event was a system user. | boolean |
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
| tags | List of keywords used to tag each event. | keyword |
