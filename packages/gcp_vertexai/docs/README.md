# GCP Vertex AI

## Overview

Vertex AI is a platform that enables the training and deployment of machine learning models and AI applications. It aims to streamline and expedite the development and deployment process for ML models, offering a variety of features and integrations tailored for enterprise-level workflows.

The integration with Google Cloud Platform (GCP) Vertex AI allows you to gather metrics such as token usage, latency, overall invocations, and error rates for deployed models. Additionally, it tracks resource utilization metrics for the model replicas as well as [prediction metrics](https://cloud.google.com/vertex-ai/docs/predictions/overview) of endpoints.

## Configuration

For fetching the metrics, users need to enter the project_id and the credentials file/json.

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
