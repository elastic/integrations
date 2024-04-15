# MongoDB Atlas Integration

## Overview

[MongoDB Atlas](https://www.mongodb.com/atlas), the leading multi-cloud developer data platform, offers the easiest way to run MongoDB, enabling you to work with your code's objects directly through its document-based data model, which allows for flexible schema and easy scalability.

Use the MongoDB Atlas integration to:

- Collect MongoDB database logs for comprehensive monitoring and analysis.
- Create informative visualizations to track usage trends, measure key metrics, and derive actionable business insights.
- Set up alerts to minimize Mean Time to Detect (MTTD) and Mean Time to Resolve (MTTR) by quickly referencing relevant logs during troubleshooting.

## Data streams

The MongoDB Atlas integration collects logs.

Logs help you keep a record of events that happen on your machine. The `Log` data stream collected by MongoDB Atlas integration is `mongod_database`.

Data stream:
- `mongod_database`: This datastream collects a running log of events, including entries such as incoming connections, commands run, and issues encountered. Generally, database log messages are useful for diagnosing issues, monitoring your deployment, and tuning performance.

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

1. Generate programmatic API keys with project owner permissions by following the instructions in the Atlas [documentation](https://www.mongodb.com/docs/atlas/configure-api-access/#create-an-api-key-for-a-project). Then, copy the public and private keys which function as a username and API key respectively.
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
- The `mongod_database` data streams gather historical data spanning the previous 30 minutes.
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

### Mongod Database

This is the `mongod_database` data stream. This datastream collects a running log of events, including entries such as incoming connections, commands run, monitoring deployment, tuning performance and issues encountered.

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
| mongodb_atlas.mongod_database.component | The component field type indicates the category a logged event is a member of, such as NETWORK or COMMAND. | keyword |
| mongodb_atlas.mongod_database.hostname | Human-readable label that identifies the host that stores the log files that you want to download. | keyword |
| mongodb_atlas.mongod_database.id | Unique identifier for the log statement. | long |
| mongodb_atlas.mongod_database.message | Log output message passed from the server or driver. If necessary, the message is escaped according to the JSON specification. | match_only_text |
| mongodb_atlas.mongod_database.size | Original size of a log entry if it has been truncated. Only included if the log entry contains at least one truncated attr attribute. | object |
| mongodb_atlas.mongod_database.tags | Strings representing any tags applicable to the log statement. For example, ["startupWarnings"]. | keyword |
| mongodb_atlas.mongod_database.thread.name | Name of the thread that caused the log statement. | keyword |
| mongodb_atlas.mongod_database.truncated | Information about the log message truncation, if applicable. Only included if the log entry contains at least one truncated attr attribute. | object |
| tags | List of keywords used to tag each event. | keyword |
