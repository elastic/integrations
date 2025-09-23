# GCP Vertex AI

## Overview

Vertex AI is a platform that enables the training and deployment of machine learning models and AI applications. It aims to streamline and expedite the development and deployment process for ML models, offering a variety of features and integrations tailored for enterprise-level workflows.

The integration with Google Cloud Platform (GCP) Vertex AI allows you to gather metrics such as token usage, latency, overall invocations, and error rates for deployed models. Additionally, it tracks resource utilization metrics for the model replicas as well as [prediction metrics](https://cloud.google.com/vertex-ai/docs/predictions/overview) of endpoints.

## Data streams

The Vertex AI integration collects metrics and logs data.

The GCP Vertex AI includes **Vertex AI Model Garden Publisher Model** metrics under the publisher category, and the **Vertex AI Endpoint** metrics under the prediction category and audit logs under the logs.

## Requirements

You need Elasticsearch to store and search your data and Kibana to visualize and manage it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your hardware.

Before using any GCP integration you will need:

### Service Account

First, you need to [create a Service Account](https://cloud.google.com/iam/docs/creating-managing-service-accounts). Service Accounts (SAs) are [principals](https://cloud.google.com/iam/docs/principals-overview) in Google Cloud, enabling you to grant them access to resources through IAM policies.


The Elastic Agent uses the SA to access data on Google Cloud Platform using the Google APIs.

### Service Account Keys

With your Service Account (SA) with access to Google Cloud Platform (GCP) resources, you need the credentials to associate with it: a Service Account Key.

From the list of SA:

1. Click the Service Account you just created to open the detailed view.
2. From the Keys section, click **Add key** > **Create new key** and select JSON as the type.
3. Download and store the generated private key securely. Note that the private key can't be recovered from GCP if lost.

### Roles and permissions

There isn't a single, specific role required to view metrics for Vertex AI. Access depends on how the models are deployed and the permissions granted to your Google Cloud project and user account. 

However, to summarize the necessary permissions and implied roles, you'll generally need a role that includes the following permissions:

- **monitoring.metricDescriptor.list:** Allows you to list available metric descriptors.
- **monitoring.timeSeries.list:** Allows you to list time series data for the metrics.

These permissions are included in many roles, but these are some of the most common ones:

- **roles/monitoring.viewer:** This role provides read-only access to Cloud Monitoring metrics.
- **roles/aiplatform.user:** This role grants broader access to Vertex AI, including model viewing and potentially metric access.
- **More granular roles:** For fine-grained control (recommended for security best practices), consider using a custom role built with the specific permissions needed. This would only include the necessary permissions to view model metrics, rather than broader access to all Vertex AI or Cloud Monitoring resources. This requires expertise in IAM (Identity and Access Management).
- **Predefined roles with broader access:** These roles provide extensive permissions within the Google Cloud project, giving access to metrics but granting much broader abilities than necessary for just viewing metrics. These are generally too permissive unless necessary for other tasks. Examples are `roles/aiplatform`.user or `roles/editor`.



## Set up and configure the integration settings

For step-by-step instructions on how to set up an integration, refer to the [Getting Started](https://www.elastic.co/guide/en/starting-with-the-elasticsearch-platform-and-its-solutions/current/getting-started-observability.html) guide.

The next step is to configure the general integration settings used for logs and metrics from the supported services.

When you add the Google Cloud Platform VertexAI integration, you need to provide the Project ID and either the Credentials File or Credentials JSON.

### Project Id

The Project Id is the Google Cloud project ID where your resources exist.

### Credentials File vs JSON

Based on your preference, specify the information in either the Credentials File or the Credentials JSON field.

#### Option 1: Credentials File

Save the JSON file with the private key in a secure location of the file system, and make sure that the Elastic Agent has at least read-only privileges to this file.

Specify the file path in the Elastic Agent integration UI in the "Credentials File" field. For example: `/home/ubuntu/credentials.json`.

#### Option 2: Credentials JSON

Specify the content of the JSON file you downloaded from Google Cloud Platform directly in the Credentials JSON field in the Elastic Agent integration.



## Metrics

With a properly configured Service Account and the integration setting in place, it's time to start collecting the monitoring metrics.

### Requirements

No additional requirements to collect metrics.

### Deployment types in Vertex AI

Vertex AI offers two primary deployment types:

- **Provisioned Throughput:** Suitable for high-usage applications with predictable workloads and a premium on guaranteed performance.
- **Pay-as-you-go:** Ideal for low-usage applications, batch processing, and applications with unpredictable traffic patterns.

Now, you can track and monitor different deployment types (provisioned throughput and pay-as-you-go) in Vertex AI using the Model Garden Publisher resource.


## Logs

With a properly configured Service Account and the integration setting in place, you can start collecting the logs.

### Requirements

#### AuditLogs

Before you start, you need to create the following Google Cloud resources:

- Log Sink
- Pub/Sub Topic
- Subscription


Here's an example of collecting Vertex AI audit logs using a Pub/Sub topic, a subscription, and a Log Router. We will create the resources in the Google Cloud Console and then configure the Google Cloud Platform integration.

On the Google Cloud Console follow these steps:

At a high level, the steps required are:

1. Visit "Logging" > "Log Router" > "Create Sink" and provide a sink name and description.
2. In "Sink destination", select "Cloud Pub/Sub topic" as the sink service. Select an existing topic or "Create a topic". Note the topic name, as it will be provided in the Topic field in the Elastic agent configuration.
3. If you created a new topic, you must remember to go to that topic and create a subscription for it. A subscription directs messages on a topic to subscribers. Note the "Subscription ID", as it will need to be entered in the "Subscription name" field in the integration settings.
4. Under "Choose logs to include in sink", for example add `resource.labels.service=aiplatform.googleapis.com` and `resource.type="audited_resource"` in the "Inclusion filter" to include all audit logs.

This is just an example to create your filter expression to select the Vertex AI audit logs  you want to export to the Pub/Sub topic.


#### Prompt Response Logging

The `prompt_response_logs` data stream is designed to collect Vertex AI prompt-response logs from GCP BigQuery. BigQuery is a fully-managed, serverless data warehouse that stores detailed logs of interactions with Vertex AI models.

Vertex AI logs export to BigQuery enables you to export detailed Google Cloud Vertex AI interaction data (such as prompts, responses, model usage, and metadata) automatically to a BigQuery dataset that you specify. Then you can access your Vertex AI logs from BigQuery for detailed analysis and monitoring using this integration. This enables comprehensive tracking of AI model usage, performance monitoring, and cost analysis.


Before you start, you need to push the Vertex AI Prompt response logs to the BigQuery Table. Please refer to this [official documentation](https://cloud.google.com/vertex-ai/generative-ai/docs/multimodal/request-response-logging_) for detailed steps. 


**Configuration**: When configuring the integration, you'll need to configure the following settings:

1. **Table ID**: (Required) Full table identifier in the format `project_id.dataset_id.table_name` that contains the Vertex AI logs data. You can copy this from the "Details" tab when viewing your table in the BigQuery web console, under the "Table ID" field.

2. **Time Lookback Hours**: (Optional) Specifies how many hours back from the current time to query for new log entries in the format `time_lookback_hours`. The default value for this is 1hr.

## Troubleshooting

Refer to [Google Cloud Platform troubleshooting](https://www.elastic.co/guide/en/integrations/current/gcp.html#_troubleshooting) for more information about troubleshooting.

## Metrics reference

{{event "metrics"}}

**ECS Field Reference**

Check the [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "metrics"}}


## Logs reference

### AuditLogs 

{{event "auditlogs"}}

**ECS Field Reference**

Check the [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "auditlogs"}}

### Prompt Response Logs 

{{event "prompt_response_logs"}}

**ECS Field Reference**

Check the [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "prompt_response_logs"}}
