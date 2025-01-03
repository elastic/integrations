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

The rate limiting parameters (`limit`: 12, `burst`: 1) are calibrated to respect OpenAI's standard rate limits of 5 requests per minute. The integration spaces requests every 12 seconds with a single concurrent request allowed.

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

new entries `usage_metrics_{3,4,...,n}` appended to the end of the log.

This append-only pattern means new usage metrics are continuously added throughout the day. Setting `collection.realtime: true` with frequent collection periods would result in duplicate data points, as each collection would gather the entire day's accumulated log.

The optimal collection strategy is to use `time.Now() (in UTC) - 24h`, which provides complete usage data for the previous day while eliminating duplicates. This is why we set `collection.realtime: false` and `period: 24h` as the recommended configuration.

With these settings, each collection gathers exactly one day's worth of data, creating clean, non-overlapping data points ideal for analytics and storage efficiency. The 24-hour delay in data availability enables complete and accurate daily usage metrics.

There's also an internal cursor that tracks the last collected timestamp. This cursor is updated after each collection to ensure that the next collection starts from the next day's data.

## Metrics reference

### Usage

The `usage` data stream captures events related to OpenAI API usage — token usage, API calls, and other related metrics for models provided by OpenAI.

An example event for `usage` looks as following:

```json
{
    "@timestamp": "2024-12-02T19:57:00.000Z",
    "agent": {
        "ephemeral_id": "a9faae61-22a0-400e-987b-6cca1a9f1e08",
        "id": "e7a75609-7dd9-4167-98ae-1d5d7405ad4d",
        "name": "docker-fleet-agent",
        "name.text": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "9.0.0"
    },
    "data_stream": {
        "dataset": "openai.usage",
        "namespace": "default",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "e7a75609-7dd9-4167-98ae-1d5d7405ad4d",
        "snapshot": true,
        "version": "9.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "openai.usage",
        "duration": 96622511294,
        "ingested": "2024-12-25T19:52:48.000Z",
        "module": "openai"
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.19.0.7"
        ],
        "mac": [
            "02-42-AC-13-00-07"
        ],
        "name": "docker-fleet-agent",
        "name.text": "docker-fleet-agent",
        "os": {
            "family": "",
            "kernel": "6.10.14-linuxkit",
            "name": "Wolfi",
            "name.text": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "metricset": {
        "name": "usage",
        "name.text": "usage",
        "period": 86400000
    },
    "openai": {
        "usage": {
            "data": {
                "cached_context_tokens_total": 0,
                "context_tokens_total": 25,
                "generated_tokens_total": 33,
                "operation": "completion",
                "request_type": "",
                "requests_total": 1,
                "snapshot_id": "gpt-4o-mini-2024-07-18"
            },
            "organization_id": "org-dummy",
            "organization_name": "Personal"
        }
    },
    "service": {
        "type": "openai"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| openai.usage.api_key_id | API key identifier | keyword |
| openai.usage.api_key_name | API key name | keyword |
| openai.usage.api_key_redacted | Redacted API key | keyword |
| openai.usage.api_key_type | Type of API key | keyword |
| openai.usage.assistant_code_interpreter.original | Raw assistant code interpreter data | object |
| openai.usage.dalle.image_size | Size of generated images | keyword |
| openai.usage.dalle.model_id | Model identifier | keyword |
| openai.usage.dalle.num_images | Number of images generated | long |
| openai.usage.dalle.operation | Operation type | keyword |
| openai.usage.dalle.requests_total | Number of requests | long |
| openai.usage.dalle.user_id | User identifier | keyword |
| openai.usage.data.cached_context_tokens_total | Total number of cached input tokens | long |
| openai.usage.data.context_tokens_total | Total number of input tokens used | long |
| openai.usage.data.email | User email | keyword |
| openai.usage.data.generated_tokens_total | Total number of output tokens | long |
| openai.usage.data.operation | Operation type | keyword |
| openai.usage.data.request_type | Type of request | keyword |
| openai.usage.data.requests_total | Number of requests made | long |
| openai.usage.data.snapshot_id | Snapshot identifier | keyword |
| openai.usage.ft_data.original | Raw fine-tuning data | object |
| openai.usage.organization_id | Organization identifier | keyword |
| openai.usage.organization_name | Organization name | keyword |
| openai.usage.project_id | Project identifier | keyword |
| openai.usage.project_name | Project name | keyword |
| openai.usage.retrieval_storage.original | Raw retrieval storage data | object |
| openai.usage.tts.model_id | Model identifier | keyword |
| openai.usage.tts.num_characters | Number of characters processed | long |
| openai.usage.tts.requests_total | Number of requests | long |
| openai.usage.tts.user_id | User identifier | keyword |
| openai.usage.whisper.model_id | Model identifier | keyword |
| openai.usage.whisper.num_seconds | Number of seconds processed | long |
| openai.usage.whisper.requests_total | Number of requests | long |
| openai.usage.whisper.user_id | User identifier | keyword |
