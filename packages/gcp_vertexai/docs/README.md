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

## Troubleshooting

Refer to [Google Cloud Platform troubleshooting](https://www.elastic.co/guide/en/integrations/current/gcp.html#_troubleshooting) for more information about troubleshooting.

## Metrics reference

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

Check the [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

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



## Logs reference

An example event for `auditlogs` looks as following:

```json
{
    "cloud": {
        "project": {
            "id": "elastic-abs"
        },
        "provider": "gcp"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "action": "google.cloud.aiplatform.internal.PredictionService.CountTokens",
        "id": "1tif4epd6kb0",
        "kind": "event"
    },
    "gcp": {
        "vertexai": {
            "audit": {
                "authentication_info": {
                    "principal_email": "pc.cf@elastic.co"
                },
                "authorization_info": [
                    {
                        "granted": true,
                        "permission": "aiplatform.endpoints.predict",
                        "permission_type": "DATA_READ",
                        "resource": "projects/elastic-abs/locations/us-central1/publishers/google/models/gemini-2.0-flash-exp"
                    }
                ],
                "request": {
                    "@type": "type.googleapis.com/google.cloud.aiplatform.internal.CountTokensRequest",
                    "endpoint": "projects/elastic-abs/locations/us-central1/publishers/google/models/gemini-2.0-flash-exp"
                },
                "resource_name": "projects/elastic-abs/locations/us-central1/publishers/google/models/gemini-2.0-flash-exp",
                "resource_type": "audited_resource",
                "response": {
                    "@type": "type.googleapis.com/google.cloud.aiplatform.internal.CountTokensResponse"
                },
                "service_name": "aiplatform.googleapis.com",
                "type": "type.googleapis.com/google.cloud.audit.AuditLog"
            }
        }
    },
    "log": {
        "level": "INFO",
        "logger": "projects/elastic-abs/logs/cloudaudit.googleapis.com%2Fdata_access"
    },
    "source": {
        "ip": "175.16.199.0"
    },
    "user_agent": {
        "device": {
            "name": "Mac"
        },
        "name": "Chrome",
        "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36,gzip(gfe),gzip(gfe)",
        "os": {
            "full": "Mac OS X 10.15.7",
            "name": "Mac OS X",
            "version": "10.15.7"
        },
        "version": "135.0.0.0"
    }
}
```

**ECS Field Reference**

Check the [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| gcp.vertexai.audit.authentication_info.authority_selector | The authority selector specified by the requestor, if any. It is not guaranteed  that the principal was allowed to use this authority. | keyword |
| gcp.vertexai.audit.authentication_info.principal_email | The email address of the authenticated user making the request. | keyword |
| gcp.vertexai.audit.authentication_info.principal_subject | String representation of identity of requesting party. Populated for both first and third party identities. Only present for APIs that support third-party identities. | keyword |
| gcp.vertexai.audit.authentication_info.service_account_delegation_info | Identity delegation history of an authenticated service account that makes the request. It contains information on the real authorities that try to access GCP resources by delegating on a service account. When multiple authorities present, they are guaranteed to be sorted based on the original ordering of the identity delegation events. | flattened |
| gcp.vertexai.audit.authentication_info.service_account_key_name | The service account key that was used to request the OAuth 2.0 access token. This field identifies the service account key by its full resource name. | keyword |
| gcp.vertexai.audit.authentication_info.third_party_principal | The third party identification (if any) of the authenticated user making the request. When the JSON object represented here has a proto equivalent, the proto name will be indicated in the @type property. | flattened |
| gcp.vertexai.audit.authorization_info | Authorization information for the operation. | nested |
| gcp.vertexai.audit.authorization_info.granted | Whether or not authorization for resource and permission was granted. | boolean |
| gcp.vertexai.audit.authorization_info.permission | The required IAM permission. | keyword |
| gcp.vertexai.audit.authorization_info.permission_type | The type of the permission, for example, DATA_READ . | keyword |
| gcp.vertexai.audit.authorization_info.resource | The resource being accessed, as a REST-style string. | keyword |
| gcp.vertexai.audit.authorization_info.resource_attributes.name | The name of the resource. | keyword |
| gcp.vertexai.audit.authorization_info.resource_attributes.service | The name of the service. | keyword |
| gcp.vertexai.audit.authorization_info.resource_attributes.type | The type of the resource. | keyword |
| gcp.vertexai.audit.metadata | Service-specific data about the request, response, and other information associated with the current audited event. | flattened |
| gcp.vertexai.audit.num_response_items | The number of items returned from a List or Query API method, if applicable. | long |
| gcp.vertexai.audit.policy_violation_info.payload | Resource payload that is currently in scope and is subjected to orgpolicy conditions. | flattened |
| gcp.vertexai.audit.policy_violation_info.resource_tags | Tags referenced on the resource at the time of evaluation. | flattened |
| gcp.vertexai.audit.policy_violation_info.resource_type | Resource type that the orgpolicy is checked against. | keyword |
| gcp.vertexai.audit.policy_violation_info.violations | Provides information about the Policy violation info for the request. | nested |
| gcp.vertexai.audit.policy_violation_info.violations.checked_value | Value that is being checked for the policy. | keyword |
| gcp.vertexai.audit.policy_violation_info.violations.constraint | Constraint name. | keyword |
| gcp.vertexai.audit.policy_violation_info.violations.error_message | Error message that policy is indicating. | keyword |
| gcp.vertexai.audit.policy_violation_info.violations.policy_type | Indicates the type of the policy. | keyword |
| gcp.vertexai.audit.request | The operation request. This may not include all request elements, such as those that are too large, privacy-sensitive, or duplicated elsewhere in the log record. When the JSON object represented here has a proto equivalent, the proto name will be indicated in the @type property | flattened |
| gcp.vertexai.audit.resource_location.current_locations | Current locations of the resource. | keyword |
| gcp.vertexai.audit.resource_name | The resource or collection that is the target of the operation.  The name is a scheme-less URI, not including the API service name.  For example, 'projects/PROJECT_ID/datasets/DATASET_ID'. | keyword |
| gcp.vertexai.audit.resource_type | Type of resource | keyword |
| gcp.vertexai.audit.response | The operation response. This may not include all response elements, such as those that are too large, privacy-sensitive, or duplicated elsewhere in the log record. When the JSON object represented here has a proto equivalent, the proto name will be indicated in the @type property. | flattened |
| gcp.vertexai.audit.service_name | The name of the API service performing the operation. | keyword |
| gcp.vertexai.audit.status.code | The status code, which should be an enum value of google.rpc.Code. | integer |
| gcp.vertexai.audit.status.details | A list of messages that carry the error details. | flattened |
| gcp.vertexai.audit.status.message | A developer-facing error message, which should be in English. Any user-facing  error message should be localized and sent in the google.rpc.Status.details  field, or localized by the client. | keyword |
| gcp.vertexai.audit.type | Type of the logs. | keyword |

