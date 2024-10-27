# GCP Vertex AI

## Overview

Vertex AI is a platform that enables the training and deployment of machine learning models and AI applications. It aims to streamline and expedite the development and deployment process for ML models, offering a variety of features and integrations tailored for enterprise-level workflows.

The integration with Google Cloud Platform (GCP) Vertex AI allows you to gather metrics such as token usage, latency, overall invocations, and error rates for deployed models. Additionally, it tracks resource utilization metrics for the model replicas as well as [prediction metrics](https://cloud.google.com/vertex-ai/docs/predictions/overview) of endpoints.

## Configuration

For fetching the metrics, users need to enter the project_id and the credentials file/json.

## Metrics

The GCP Vertex AI includes **Vertex AI Model Garden Publisher Model** metrics under the publisher category and the **Vertex AI Endpoint** metrics under the prediction category.

{{fields "metrics"}}