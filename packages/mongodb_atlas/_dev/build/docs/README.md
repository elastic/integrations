# MongoDB Atlas Integration

## Overview

[MongoDB Atlas](https://www.mongodb.com/atlas), the leading multi-cloud developer data platform, offers the easiest way to run MongoDB, enabling you to work with your code's objects directly through its document-based data model, which allows for flexible schema and easy scalability.

Use the MongoDB Atlas integration to:

- Collect MongoDB Atlas mongod audit, mongod database, organization and project logs, along with disk, hardware and process metrics for comprehensive monitoring and analysis.
- Create informative visualizations to track usage trends, measure key metrics, and derive actionable business insights.
- Set up alerts to minimize Mean Time to Detect (MTTD) and Mean Time to Resolve (MTTR) by quickly referencing relevant logs during troubleshooting.

## Data streams

The MongoDB Atlas integration collects logs and metrics.

Logs help you keep a record of events that happen on your machine. The `Log` data stream collected by MongoDB Atlas integration are `mongod_audit`, `mongod_database`, `organization`, and `project`.

Metrics give you insight into the statistics of the MongoDB Atlas. The `Metric` data stream collected by the MongoDB Atlas integration are `disk`, `hardware`, and `process` so that the user can monitor and troubleshoot the performance of the MongoDB Atlas instance.

Data streams:
- `disk`: This data stream collects metrics of disk or partition for all the hosts in the specified group. Metrics like measurements for the disk, such as I/O operations, read and write latency, and space usage.
- `hardware`: This data stream collects all the Atlas search hardware and status data series within the provided time range for one process in the specified project.
- `mongod_audit`: The auditing facility allows administrators and users to track system activity for deployments with multiple users and applications. Mongod Audit logs capture events related to database operations such as insertions, updates, deletions, user authentication, etc., occurring within the mongod instances.
- `mongod_database`: This data stream collects a running log of events, including entries such as incoming connections, commands run, and issues encountered. Generally, database log messages are useful for diagnosing issues, monitoring your deployment, and tuning performance.
- `organization`: Organization logs provide a detailed view of your organization's activities, enabling tracking and monitoring of significant actions and status changes involving database operations, billing, security, hosts, encryption, user access, and more, as performed by users and teams.
- `process`: This data stream collects host metrics per process for all the hosts in the specified group. Metrics like measurements for the host, such as CPU usage, number of I/O operations and memory usage are available in this data stream.
- `project`: This data stream collects events from MongoDB Atlas, providing a comprehensive record of actions and changes made within a project. These events can include modifications to database configurations, user access changes, and general project activity. It's a crucial resource for auditing and monitoring the activities within a MongoDB Atlas project.

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
- The `mongod_audit`, `mongod_database`, `organization`, and `project` data streams gather historical data spanning the previous 30 minutes.
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

{{event "mongod_audit"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "mongod_audit"}}

### Mongod Database

This is the `mongod_database` data stream. This data stream collects a running log of events, including entries such as incoming connections, commands run, monitoring deployment, tuning performance, and issues encountered. To collect database logs, the requesting API Key must have the `Project Data Access Read Only` or higher role.

{{event "mongod_database"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "mongod_database"}}

### Organization

This is the `organization` data stream. This data stream collects detailed view of your organization's activities, enabling tracking and monitoring of significant actions and status changes involving database operations, billing, security, hosts, encryption, user access, and more, as performed by users and teams.

{{event "organization"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "organization"}}

### Project

This is the `project` data stream. This data stream collects events from MongoDB Atlas, providing a comprehensive record of actions and changes made within a project. These events can include modifications to database configurations, user access changes, and general project activity. It's a crucial resource for auditing and monitoring the activities within a MongoDB Atlas project. To collect project logs, the requesting API Key must have the `Project Read Only` role.

{{event "project"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "project"}}

## Metrics reference

## Disk

This is the `disk` data stream. This data stream collects detailed view on disk usage and captures crucial information about I/O operations, read and write latency, and space utilization. To collect disk metrics, the requesting API Key must have the `Project Read Only` role.

{{event "disk"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "disk"}}

### Hardware

This is the `hardware` data stream. This data stream collects hardware and status metrics for each process in the specified group. It includes measurements such as CPU usage, memory consumption, JVM memory usage, disk usage, etc. To collect hardware metrics, the requesting API Key must have the `Project Read Only` or higher role.

{{event "hardware"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "hardware"}}

### Process

This is the `process` data stream. This data stream collects host metrics per process for all the hosts of the specified group. Metrics like measurements for the host, such as CPU usage, number of I/O operations and memory are available on this data stream. To collect process metrics, the requesting API Key must have the `Project Read Only` role.

{{event "process"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "process"}}