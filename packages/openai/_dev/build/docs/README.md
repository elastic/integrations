# OpenAI metrics

The OpenAI metrics integration allows you to monitor OpenAI API usage and performance. OpenAI is a leading AI platform providing various AI models and APIs for natural language processing, image generation, and other AI capabilities.

Use the OpenAI metrics integration to track API usage, costs, and performance metrics across your OpenAI implementations. Then visualize that data in Kibana, create alerts to notify you if usage limits are approaching, and reference metrics when troubleshooting API issues.

For example, if you wanted to monitor costs across different OpenAI models, you could track token usage and API calls per model. Then you can visualize various trends in Kibana dashboards, set up alerts for unusual usage spikes, or troubleshoot by analyzing number of requests, etc.

## Data collection

The OpenAI metrics integration collects comprehensive usage data through the OpenAI API endpoint `https://api.openai.com/v1/usage`. This endpoint provides detailed metrics about your API consumption and usage patterns across your organization.

The integration works by querying the endpoint using the format `https://api.openai.com/v1/usage?date=YYYY-MM-DD`. Authentication happens via API key passed in the request header as `Authorization: Bearer <API_KEY>`. The endpoint returns daily aggregated usage metrics for the specified date, including token usage, request counts, and model-specific metrics.

>**Note**: While this API endpoint is functional, it is currently undocumented in OpenAI's official documentation. As with any undocumented API, the endpoint's structure and behavior may evolve over time. The endpoint could also change or be removed at any time without warning. Organizations using this should have contingency plans in place for potential API disruptions.

## Data streams

The OpenAI metrics integration collects one type of data stream: metrics.

**Metrics** give you insight into the state of OpenAI API usage.
Metric data streams collected by the OpenAI integration include `usage` data stream. See more details in the [Metrics](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

You need an OpenAI account to access the API with a valid API key.

>**Note**: OpenAI's "project" system enables customers to organize their work through multiple projects, each supporting multiple API keys. For this integration, you must use the API key from the "Default" project. When using the Default project's API key, the API endpoint provides comprehensive usage metrics across all projects within your organization. While this functionality effectively delivers organization-wide metrics, it's important to understand that it relies on an undocumented API feature. As with any undocumented API usage, this functionality may be subject to changes in future OpenAI updates.

## Configuration

The configuration parameters serve specific purposes:

* Period: The interval at which metrics are collected. Defaults to 24 hours.
* OpenAI API key: The API key used to authenticate with the OpenAI API. Required field.
* OpenAI usage API endpoint: The URL of the OpenAI usage API endpoint. Defaults to `https://api.openai.com/v1/usage`. This is useful if you want to use a custom API endpoint.
* Custom headers: Custom headers to be included in the API requests. Optional field.
* Rate limit (limit): The rate limit for the OpenAI API. Defaults to 12.
* Rate limit (burst): The burst rate for the OpenAI API. Defaults to 1.
* Request timeout: The timeout for API requests. Defaults to 30 seconds.
* Lookback days: The number of days to look back for collection. Defaults to 30.
* Realtime data collection: Whether to collect data in real-time. Defaults to false.

The period parameter defaults to `24h` (24 hours) to align with OpenAI's usage data availability. This timing ensures complete daily metrics while preventing duplicate data collection. Your API key from the "Default" project enables access to organization-wide metrics across all projects.

The rate limiting parameters (**limit: 12**, **burst: 1**) are calibrated to respect OpenAI's standard rate limits of **5 requests per minute**. The integration spaces requests **every 12 seconds with a single concurrent request** allowed.

The lookback days parameter determines how much historical data to fetch on initial setup. The default 30-day lookback provides a comprehensive view of recent usage patterns while maintaining reasonable data volumes.

### Collection behavior

The OpenAI usage API implements an append-only log pattern for metrics collection. Understanding this behavior is crucial for optimal data gathering.

For example:

Given timestamps `t0`, `t1`, `t2`, ... `tn` in ascending order:

* At `t0` (first collection):
```
usage_metrics_1: *
```
new entry `usage_metrics_1` added to the empty log.

* At `t1` (continuous collection):
```
usage_metrics_1: *
usage_metrics_2: *
```
new entry `usage_metrics_2` appended to the end of the log.

* At `tn` (continuous collection):
```
usage_metrics_1: *
usage_metrics_2: *
usage_metrics_3: *
...
usage_metrics_n: *
```

new entries `usage_metrics_{3,...,n}` appended to the end of the log.

This append-only pattern means new usage metrics are continuously added throughout the day. Setting `collection.realtime: true` with frequent collection periods would result in duplicate data points, as each collection would gather the entire day's accumulated log.

The optimal collection strategy is to use `current time (in UTC) - 24h`, which provides complete usage data for the previous day while eliminating duplicates. This is why we set `collection.realtime: false` and `period: 24h` as the recommended configuration, as the full daily data becomes available the following day.

With these settings, each collection gathers exactly one day's worth of data, creating clean, non-overlapping data points ideal for analytics and storage efficiency. The 24-hour delay in data availability enables complete and accurate daily usage metrics.

There's also an internal cursor that tracks the last collected timestamp. This cursor is updated after each collection to ensure that the next collection starts from the next day's data.

## Metrics reference

### Usage

The `usage` data stream captures events related to OpenAI API usage — token usage, API calls, and other related metrics for models provided by OpenAI.

{{event "usage"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "usage"}}