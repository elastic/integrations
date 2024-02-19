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
- `mongod_audit`: The auditing facility allows administrators and users to track system activity for deployments with multiple users and applications.

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

## Troubleshooting

- If the user encounters the following error during data ingestion, it is likely due to the data collected through this endpoint covers a long time span. As a result, generating a response may take longer. Additionally, if the `HTTP Client Timeout` parameter is set to a small duration,  a request timeout might happen. It is important to note that no data will be lost in this scenario. However, if the user wishes to avoid this error altogether, it is recommended to adjust the `HTTP Client Timeout` and `Interval` parameters based on the duration of data collection.
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

{{fields "mongod_audit"}}