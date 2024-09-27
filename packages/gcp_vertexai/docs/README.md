# GCP Vertex AI

## Overview

The Vertex AI is a platform that lets you train and deploy ML models and AI applications.
Vertex AI is designed to simplify and accelerate the development and deployment of ML models, and provides a wide range of features and integrations for enterprise-level ML workflows.

The GCP Vertex AI integration allows you to collect the token usage, latency, overall requests and the error rates for the deployed models. 
This integration also collects CPU and memory usage related to the replicas of the deployed models.

## Metrics

The GCP Vertex AI includes **Vertex AI Model Garden Publisher Model** metrics under the publisher category and the **Vertex AI Endpoint** metrics under the prediction category.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| gcp.labels.resource.location | Location of the resource | keyword |  |  |
| gcp.vertexai.prediction.online.cpu.utilization | Fraction of CPU allocated by the deployed model replica and currently in use. May exceed 100% if the machine type has multiple CPUs. Sampled every 60 seconds. After sampling data is not visible for up to 360 seconds. | double |  | gauge |
| gcp.vertexai.prediction.online.error_count | Number of online prediction errors. | long |  |  |
| gcp.vertexai.prediction.online.memory.bytes_used | Amount of memory allocated by the deployed model replica and currently in use. Sampled every 60 seconds. After sampling data is not visible for up to 360 seconds. | long | byte | gauge |
| gcp.vertexai.prediction.online.network.received_bytes_count | Number of bytes received over the network by the deployed model replica. Sampled every 60 seconds. After sampling data is not visible for up to 360 seconds. | long | byte |  |
| gcp.vertexai.prediction.online.network.sent_bytes_count | Number of bytes sent over the network by the deployed model replica. Sampled every 60 seconds. After sampling data is not visible for up to 360 seconds. | long | byte |  |
| gcp.vertexai.prediction.online.prediction_count | Number of online predictions. | long |  |  |
| gcp.vertexai.prediction.online.prediction_latencies | Online prediction latency of the deployed model. | histogram |  |  |
| gcp.vertexai.prediction.online.replicas | Number of active replicas used by the deployed model. | long |  | gauge |
| gcp.vertexai.prediction.online.response_count | Number of different online prediction response codes. | long |  |  |
| gcp.vertexai.prediction.online.target_replicas | Target number of active replicas needed for the deployed model. | long |  | gauge |
| gcp.vertexai.publisher.online_serving.character_count | Accumulated input/output character count. | long |  |  |
| gcp.vertexai.publisher.online_serving.consumed_throughput | Overall throughput used (accounting for burndown rate) in terms of characters. | long |  |  |
| gcp.vertexai.publisher.online_serving.model_invocation_count | Number of model invocations (prediction requests). | long |  |  |
| gcp.vertexai.publisher.online_serving.model_invocation_latencies | Model invocation latencies (prediction latencies). | histogram |  |  |
| gcp.vertexai.publisher.online_serving.token_count | Accumulated input/output token count. | long |  |  |
