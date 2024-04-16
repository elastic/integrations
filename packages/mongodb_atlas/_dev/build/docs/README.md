# MongoDB Atlas Integration

## Overview

[MongoDB Atlas](https://www.mongodb.com/atlas), the leading multi-cloud developer data platform, offers the easiest way to run MongoDB, enabling you to work with your code's objects directly through its document-based data model, which allows for flexible schema and easy scalability.

Use the MongoDB Atlas integration to:

- Collect MongoDB Audit logs and Process metrics for comprehensive monitoring and analysis.
- Create informative visualizations to track usage trends, measure key metrics, and derive actionable business insights.
- Set up alerts to minimize Mean Time to Detect (MTTD) and Mean Time to Resolve (MTTR) by quickly referencing relevant logs during troubleshooting.

## Data streams

The MongoDB Atlas integration collects logs and metrics.

Logs help you keep a record of events that happen on your machine. The `Log` data stream collected by MongoDB Atlas integration is `mongod_audit`.

Metrics give you insight into the statistics of the MongoDB Atlas. The `Metric` data stream collected by the MongoDB Atlas integration is `process` so that the user can monitor and troubleshoot the performance of the MongoDB Atlas instance.

Data streams:
- `mongod_audit`: The auditing facility allows administrators and users to track system activity for deployments with multiple users and applications. Mongod Audit logs capture events related to database operations such as insertions, updates, deletions, user authentication, etc., occurring within the mongod instances.

- `process` : This data stream collects host metrics per process for all the hosts of the specified group. Metrics like measurements for the host, such as CPU usage, number of I/O operations and memory are available on this data stream.

Note:
- Users can monitor and see the log inside the ingested documents for MongoDB Atlas in the `logs-*` index pattern from `Discover`.

## Prerequisites

You can store and search your data using Elasticsearch and visualize and manage it with Kibana. We recommend using our hosted Elasticsearch Service on Elastic Cloud or self-managing the Elastic Stack on your own hardware.

## Setup

### To collect data from MongoDB Atlas, the following parameters from your MongoDB Atlas instance are required

1. Public Key
2. Private Key
3. GroupId

### Steps to obtain Public Key, Private Key and GroupId

1. Generate programmatic API Keys with project owner permissions using the instructions in the Atlas [documentation](https://www.mongodb.com/docs/atlas/configure-api-access/#create-an-api-key-for-a-project). Then, copy the public key and private key. These serve the same function as a username and API Key respectively.
2. Enable Database Auditing for the Atlas project you want to monitor logs. You can follow the instructions provided in this Atlas [document](https://www.mongodb.com/docs/atlas/database-auditing/#procedure).
3. You can find your Project ID (Group ID) in the Atlas UI. To do this, navigate to your project, click on Settings, and copy the Project ID (Group ID). You can also programmatically find it using the Atlas Admin API or Atlas CLI as described in this Atlas [document](https://www.mongodb.com/docs/atlas/app-services/apps/metadata/#find-a-project-id).

### Important terms of MongoDB Atlas API

1. Granularity: Duration that specifies the interval at which Atlas reports the metrics.
2. Period: Duration over which Atlas reports the metrics.

Note: Both of above attributes can be set by using `period` in configuration parameters.

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

{{event "mongod_audit"}}

{{fields "mongod_audit"}}

## Metrics reference

### Process
This data stream collects host metrics per process for all the hosts of the specified group. Metrics like measurements for the host, such as CPU usage, number of I/O operations and memory are available on this data stream.

{{event "process"}}

{{fields "process"}}
