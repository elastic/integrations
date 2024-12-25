# OpenAI metrics

The OpenAI metrics integration allows you to monitor OpenAI API usage and performance. OpenAI is a leading AI platform providing various AI models and APIs for natural language processing, image generation, and other AI capabilities.

Use the OpenAI metrics integration to track API usage, costs, and performance metrics across your OpenAI implementations. Then visualize that data in Kibana, create alerts to notify you if usage limits are approaching, and reference metrics when troubleshooting API issues.

For example, if you wanted to monitor costs across different OpenAI models, you could track token usage and API calls per model. Then you can visualize various trends in Kibana dashboards, set up alerts for unusual usage spikes, or troubleshoot by analyzing number of requests, etc.

## Data streams

The OpenAI metrics integration collects one type of data stream: metrics.

**Metrics** give you insight into the state of OpenAI API usage.
Metric data streams collected by the OpenAI integration include `usage` data stream. See more details in the [Metrics](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

You need an OpenAI account to access the API with a valid API key.

## Metrics reference

### Usage

The `usage` data stream captures events related to OpenAI API usage — token usage, API calls, etc.

{{event "usage"}}

{{fields "usage"}}