# GCP Vertex AI

## Overview

Vertex AI is a platform that enables the training and deployment of machine learning models and AI applications. It aims to streamline and expedite the development and deployment process for ML models, offering a variety of features and integrations tailored for enterprise-level workflows.

The integration with Google Cloud Platform (GCP) Vertex AI allows you to gather metrics such as token usage, latency, overall invocations, and error rates for deployed models. Additionally, it tracks resource utilization metrics for the model replicas as well as [prediction metrics](https://cloud.google.com/vertex-ai/docs/predictions/overview) of endpoints.

## Data streams

### Metrics

The GCP Vertex AI includes **Vertex AI Model Garden Publisher Model** metrics under the publisher category and the **Vertex AI Endpoint** metrics under the prediction category.

#### Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any GCP integration you will need:

* **GCP Credentials** to connect with your GCP account.
* **GCP Permissions** to make sure the service account you're using to connect has permission to share the relevant data.

#### Roles & Permissions

There isn't a single, specific role required to view metrics for Vertex AI. Access depends on how the models are deployed and the permissions granted to your Google Cloud project and user account. 

However, to summarize the necessary permissions and implied roles, you'll generally need a role that includes the following permissions:

- **monitoring.metricDescriptor.list:** Allows you to list available metric descriptors.
- **monitoring.timeSeries.list:** Allows you to list time series data for the metrics.

These permissions are included in many roles, but here are some of the most common ones:

- **roles/monitoring.viewer:** This role provides read-only access to Cloud Monitoring metrics.
- **roles/aiplatform.user:** This role grants broader access to Vertex AI, including model viewing and potentially metric access.
- **More granular roles:** For fine-grained control (recommended for security best practices), consider using a custom role built with the specific permissions needed. This would only include the necessary permissions to view model metrics, rather than broader access to all Vertex AI or Cloud Monitoring resources. This requires expertise in IAM (Identity and Access Management).
- **Predefined roles with broader access:** These roles provide extensive permissions within the Google Cloud project, giving access to metrics but granting much broader abilities than necessary for just viewing metrics. These are generally too permissive unless necessary for other tasks. Examples are `roles/aiplatform`.user or `roles/editor`.

#### Deployment Types in Vertex AI:

Vertex AI offers two primary deployment types,

- **Provisioned Throughput:** Suitable for high-usage applications with predictable workloads and a premium on guaranteed performance.
- **Pay-as-you-go:** Ideal for low-usage applications, batch processing, and applications with unpredictable traffic patterns.

Now, you can track and monitor different deployment types (provisioned throughput and pay-as-you-go) in Vertex AI using the Model Garden Publisher resource.

#### Configuration

To fetch the metrics, enter the project_id and the credentials file/json.

Refer to [Google Cloud Platform configuration](https://www.elastic.co/docs/current/integrations/gcp#configure-the-integration-settings) for more information about the configuration.

#### Troubleshooting

Refer to [Google Cloud Platform troubleshooting](https://www.elastic.co/docs/current/integrations/gcp#metrics-collection-configuration:~:text=to%20collect%20metrics.-,Troubleshooting,-If%20you%20don%27t) for more information about troubleshooting the issue.

#### Metrics reference

An example event for `metrics` looks as following:

```json
{
    "cloud": {
        "provider": "gcp",
        "account": {
            "name": "elastic-sa",
            "id": "elastic-sa"
        }
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "f9c4beb9-c0c0-47ca-963a-a9dc00e2df5e",
        "ephemeral_id": "6c42a949-d522-44bf-818b-12c4a5908b90",
        "type": "metricbeat",
        "version": "8.15.2"
    },
    "@timestamp": "2024-11-07T05:50:40.000Z",
    "ecs": {
        "version": "8.0.0"
    },
    "gcp": {
        "vertexai": {
            "publisher": {
                "online_serving": {
                    "token_count": 13
                }
            }
        },
        "labels": {
            "resource": {
                "model_user_id": "gemini-1.5-flash-002",
                "model_version_id": "",
                "publisher": "google",
                "location": "us-central1"
            },
            "metrics": {
                "request_type": "shared",
                "type": "input"
            }
        }
    },
    "service": {
        "type": "gcp"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "gcp_vertexai.metrics"
    },
    "elastic_agent": {
        "id": "f9c4beb9-c0c0-47ca-963a-a9dc00e2df5e",
        "version": "8.15.2",
        "snapshot": false
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.25.0.7"
        ]
    },
    "metricset": {
        "period": 60000,
        "name": "metrics"
    },
    "event": {
        "duration": 913154084,
        "agent_id_status": "verified",
        "ingested": "2024-11-07T05:57:17Z",
        "module": "gcp",
        "dataset": "gcp_vertexai.metrics"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| gcp.labels.metrics.deployed_model_id | The ID of the DeployedModel which serves the prediction request. | keyword |  |  |
| gcp.labels.metrics.error_category | Response error category of the request (user/system/capacity). | keyword |  |  |
| gcp.labels.metrics.input_token_size | The bucketized size of number of tokens in the prediction request. | keyword |  |  |
| gcp.labels.metrics.latency_type | The type of latency for the prediction request (either model or overhead). | keyword |  |  |
| gcp.labels.metrics.max_token_size | The bucketized max size of number of tokens in the prediction request/response. | keyword |  |  |
| gcp.labels.metrics.method | The type of method of the request (RawPredict/StreamRawPredict/ChatCompletions/etc). | keyword |  |  |
| gcp.labels.metrics.output_token_size | The bucketized size of number of tokens in the prediction response. | keyword |  |  |
| gcp.labels.metrics.replica_id | Unique ID corresponding to the model replica. | keyword |  |  |
| gcp.labels.metrics.request_type | The type of traffic of the request (dedicated/shared). | keyword |  |  |
| gcp.labels.metrics.response_code | Response code of prediction request. | keyword |  |  |
| gcp.labels.metrics.spot | Whether this deployment is on Spot VMs. Has values of True or False. | keyword |  |  |
| gcp.labels.metrics.type | Type of token (input/output). | keyword |  |  |
| gcp.labels.resource.endpoint_id | The ID of the Endpoint. | keyword |  |  |
| gcp.labels.resource.location | The region in which the service is running. | keyword |  |  |
| gcp.labels.resource.model_user_id | The resource ID of the PublisherModel. | keyword |  |  |
| gcp.labels.resource.model_version_id | The version ID of the PublisherModel. | keyword |  |  |
| gcp.labels.resource.publisher | The publisher of the model. | keyword |  |  |
| gcp.labels.resource.resource_container | The identifier of the GCP Project owning the Endpoint. | keyword |  |  |
| gcp.vertexai.prediction.online.cpu.utilization | Fraction of CPU allocated by the deployed model replica and currently in use. May exceed 100% if the machine type has multiple CPUs. Sampled every 60 seconds. After sampling data is not visible for up to 360 seconds. | double | percent | gauge |
| gcp.vertexai.prediction.online.error_count | Number of online prediction errors. | long |  | gauge |
| gcp.vertexai.prediction.online.memory.bytes_used | Amount of memory allocated by the deployed model replica and currently in use. Sampled every 60 seconds. After sampling data is not visible for up to 360 seconds. | long | byte | gauge |
| gcp.vertexai.prediction.online.network.received_bytes_count | Number of bytes received over the network by the deployed model replica. Sampled every 60 seconds. After sampling data is not visible for up to 360 seconds. | long | byte | gauge |
| gcp.vertexai.prediction.online.network.sent_bytes_count | Number of bytes sent over the network by the deployed model replica. Sampled every 60 seconds. After sampling data is not visible for up to 360 seconds. | long | byte | gauge |
| gcp.vertexai.prediction.online.prediction_count | Number of online predictions. | long |  | gauge |
| gcp.vertexai.prediction.online.prediction_latencies | Online prediction latency of the deployed model. | histogram |  |  |
| gcp.vertexai.prediction.online.replicas | Number of active replicas used by the deployed model. | long |  | gauge |
| gcp.vertexai.prediction.online.response_count | Number of different online prediction response codes. | long |  | gauge |
| gcp.vertexai.prediction.online.target_replicas | Target number of active replicas needed for the deployed model. | long |  | gauge |
| gcp.vertexai.publisher.online_serving.character_count | Accumulated input/output character count. | long |  | gauge |
| gcp.vertexai.publisher.online_serving.consumed_throughput | Overall throughput used (accounting for burndown rate) in terms of characters. | long |  | gauge |
| gcp.vertexai.publisher.online_serving.first_token_latencies | Duration from request received to first token sent back to the client | histogram |  |  |
| gcp.vertexai.publisher.online_serving.model_invocation_count | Number of model invocations (prediction requests). | long |  | gauge |
| gcp.vertexai.publisher.online_serving.model_invocation_latencies | Model invocation latencies (prediction latencies). | histogram |  |  |
| gcp.vertexai.publisher.online_serving.token_count | Accumulated input/output token count. | long |  | gauge |
