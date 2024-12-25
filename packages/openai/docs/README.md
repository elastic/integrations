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

An example event for `usage` looks as following:

```json
{
    "@timestamp": [
        "2024-12-02T19:57:00.000Z"
    ],
    "agent.ephemeral_id": [
        "a9faae61-22a0-400e-987b-6cca1a9f1e08"
    ],
    "agent.id": [
        "e7a75609-7dd9-4167-98ae-1d5d7405ad4d"
    ],
    "agent.name": [
        "docker-fleet-agent"
    ],
    "agent.name.text": [
        "docker-fleet-agent"
    ],
    "agent.type": [
        "metricbeat"
    ],
    "agent.version": [
        "9.0.0"
    ],
    "data_stream.dataset": [
        "openai.usage"
    ],
    "data_stream.namespace": [
        "default"
    ],
    "data_stream.type": [
        "metrics"
    ],
    "ecs.version": [
        "8.0.0"
    ],
    "elastic_agent.id": [
        "e7a75609-7dd9-4167-98ae-1d5d7405ad4d"
    ],
    "elastic_agent.snapshot": [
        true
    ],
    "elastic_agent.version": [
        "9.0.0"
    ],
    "event.agent_id_status": [
        "verified"
    ],
    "event.dataset": [
        "openai.usage"
    ],
    "event.duration": [
        96622511294
    ],
    "event.ingested": [
        "2024-12-25T19:52:48.000Z"
    ],
    "event.module": [
        "openai"
    ],
    "host.architecture": [
        "aarch64"
    ],
    "host.containerized": [
        false
    ],
    "host.hostname": [
        "docker-fleet-agent"
    ],
    "host.ip": [
        "172.19.0.7"
    ],
    "host.mac": [
        "02-42-AC-13-00-07"
    ],
    "host.name": [
        "docker-fleet-agent"
    ],
    "host.name.text": [
        "docker-fleet-agent"
    ],
    "host.os.family": [
        ""
    ],
    "host.os.kernel": [
        "6.10.14-linuxkit"
    ],
    "host.os.name": [
        "Wolfi"
    ],
    "host.os.name.text": [
        "Wolfi"
    ],
    "host.os.platform": [
        "wolfi"
    ],
    "host.os.type": [
        "linux"
    ],
    "host.os.version": [
        "20230201"
    ],
    "metricset.name": [
        "usage"
    ],
    "metricset.name.text": [
        "usage"
    ],
    "metricset.period": [
        86400000
    ],
    "openai.usage.data.cached_context_tokens_total": [
        0
    ],
    "openai.usage.data.context_tokens_total": [
        25
    ],
    "openai.usage.data.generated_tokens_total": [
        33
    ],
    "openai.usage.data.operation": [
        "completion"
    ],
    "openai.usage.data.request_type": [
        ""
    ],
    "openai.usage.data.requests_total": [
        1
    ],
    "openai.usage.data.snapshot_id": [
        "gpt-4o-mini-2024-07-18"
    ],
    "openai.usage.organization_id": [
        "org-dummy"
    ],
    "openai.usage.organization_name": [
        "Personal"
    ],
    "service.type": [
        "openai"
    ],
    "_id": "Ilxh_5MBV_m_zutcBruN",
    "_index": ".ds-metrics-openai.usage-default-2024.12.25-000001",
    "_score": null
}
```

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
| openai.usage.data.cached_context_tokens_total | Total number of cached context tokens | long |
| openai.usage.data.context_tokens_total | Total number of context tokens used | long |
| openai.usage.data.email | User email | keyword |
| openai.usage.data.generated_tokens_total | Total number of generated tokens | long |
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
