# OpenAI

The OpenAI integration allows you to monitor OpenAI API usage metrics. OpenAI is an AI research and deployment company that offers [API platform](https://openai.com/api) for their industry-leading foundation models.

With the OpenAI integration, you can track API usage metrics across their models, as well as for vector store and code interpreter. You will use Kibana to visualize your data, create alerts if usage limits are approaching, and view metrics when you troubleshoot issues. For example, you can track token usage and API calls per model.

## Data collection

The OpenAI integration leverages the [OpenAI Usage API](https://platform.openai.com/docs/api-reference/usage) to collect detailed usage metrics. The Usage API delivers comprehensive insights into your API activity, helping you understand and optimize your organization's OpenAI API usage.

## Data streams

The OpenAI integration collects the following data streams:

- `audio_speeches`: Collects audio speeches usage metrics.
- `audio_transcriptions`: Collects audio transcriptions usage metrics.
- `code_interpreter_sessions`: Collects code interpreter sessions usage metrics.
- `completions`: Collects completions usage metrics.
- `embeddings`: Collects embeddings usage metrics.
- `images`: Collects images usage metrics.
- `moderations`: Collects moderations usage metrics.
- `vector_stores`: Collects vector stores usage metrics.

> Note: Users can view OpenAI metrics in the `logs-*` index pattern using Kibana Discover.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.

You need an OpenAI account with a valid [Admin key](https://platform.openai.com/settings/organization/admin-keys) for programmatic access to [OpenAI Usage API](https://platform.openai.com/docs/api-reference/usage).

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/starting-with-the-elasticsearch-platform-and-its-solutions/current/getting-started-observability.html) guide.

### Generate an Admin key

To generate an Admin key, please generate a key or use an existing one from the [Admin keys](https://platform.openai.com/settings/organization/admin-keys) page. Use the Admin key to configure the OpenAI integration.

## Collection behavior

Among the configuration options for the OpenAI integration, the following settings are particularly relevant: "Initial interval" and "Bucket width".

### Initial interval

- Controls the historical data collection window at startup
- Default value: 24 hours (`24h`)
- Purpose: Loads historical context when you first set up the integration

### Bucket width

A "bucket" refers to a time interval where OpenAI usage data is grouped together for reporting purposes. For example, with a 1-minute bucket width, usage metrics are aggregated minute by minute. With a 1-hour bucket width, all activity during that hour is consolidated into a single bucket. The [bucket width](https://platform.openai.com/docs/api-reference/usage/completions#usage-completions-bucket_width) determines your data's granularity and level of detail in your usage reporting.

- Controls the time-based aggregation of metrics
- Default: `1m` (1 minute)
- Options: `1m` (1 minute), `1h` (1 hour), `1d` (1 day)
- Affects API request frequency and data resolution

#### Impact on data resolution

- `1m` buckets provide the highest resolution metrics, with data arriving in near real-time (1-minute delay)
- `1h` buckets aggregate hourly, with data arriving less frequently (1-hour delay)
- `1d` buckets aggregate daily, with data arriving once per day (24-hour delay)

Data granularity relationship: `1m` > `1h` > `1d`

#### Storage considerations

Bucket width choice affects storage usage (in Elasticsearch) and data resolution:

- `1m`: Maximum granularity, higher storage needs, ideal for detailed analysis.
- `1h`: Medium granularity, moderate storage needs, good for hourly patterns.
- `1d`: Minimum granularity, lowest storage needs, suitable for long-term analysis.

Example: For 100 API calls to a particular model per hour:
- `1m` buckets: Up to 100 documents
- `1h` buckets: 1 aggregated document
- `1d` buckets: 1 daily document

#### API request impact

"Bucket width" and "Initial interval" directly affect API request frequency. When using a 1-minute bucket width, it's strongly recommended to set the "Initial interval" to a shorter duration, optimally 1-day, to ensure smooth performance. While our extensive testing demonstrates excellent results with a 6-month initial interval paired with a 1-day bucket width, the same level of success isn't achievable with 1-minute or 1-hour bucket widths. This is because the OpenAI Usage API returns different bucket quantities based on width (60 buckets per call for 1-minute, 24 for 1-hour, and 7 for 1-day widths). To achieve the best results when gathering historical data over long periods, using 1-day bucket width is the most effective method, ensuring a balance between data granularity and API limitations.

> For optimal results with historical data, use 1-day bucket widths for long periods (15+ days), 1-hour for medium periods (1-15 days), and 1-minute only for the most recent 24 hours of data.

### Collection process

With default settings (Interval: `5m`, Bucket width: `1m`, Initial interval: `24h`), the OpenAI integration follows this collection pattern:

1. Starts collection from (current_time - initial_interval)
2. Collects data up to (current_time - bucket_width)
3. Excludes incomplete current bucket for data accuracy and wait for bucket completion
4. Runs every 5 minutes by default (configurable)
5. From second collection, start from end of previous bucket timestamp and collect up to (current_time - bucket_width)

#### Example timeline

With default settings (Interval: `5m`, Bucket width: `1m`, Initial interval: `24h`):

The integration starts at 10:00 AM, collects data from 10:00 AM the previous day, and continues until 9:59 AM the current day. The next collection starts at 10:05 AM, collecting from the 10:00 AM bucket to the 10:04 AM bucket, as the "Interval" is 5 minutes.

## Metrics reference

**ECS Field Reference**

Refer to this [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

### Audio speeches

The `audio_speeches` data stream captures audio speeches usage metrics.

An example event for `audio_speeches` looks as following:

```json
{
    "openai": {
        "audio_speeches": {
            "characters": 45
        },
        "base": {
            "start_time": "2024-09-05T00:00:00.000Z",
            "num_model_requests": 1,
            "project_id": "proj_dummy",
            "user_id": "user-dummy",
            "end_time": "2024-09-06T00:00:00.000Z",
            "model": "tts-1",
            "api_key_id": "key_dummy",
            "usage_object_type": "organization.usage.audio_speeches.result"
        }
    },
    "@timestamp": "2024-09-05T00:00:00.000Z",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "openai.audio_speeches"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-28T21:56:19Z",
        "created": "2025-01-28T21:56:18.550Z",
        "kind": "metric",
        "dataset": "openai.audio_speeches"
    },
    "tags": [
        "forwarded",
        "openai-audio-speeches"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| openai.audio_speeches.characters | Number of characters processed | long |
| openai.base.api_key_id | Identifier for the API key used | keyword |
| openai.base.end_time | End timestamp of the usage bucket | date |
| openai.base.model | Name of the OpenAI model used | keyword |
| openai.base.num_model_requests | Number of requests made to the model | long |
| openai.base.project_id | Identifier of the project | keyword |
| openai.base.start_time | Start timestamp of the usage bucket | date |
| openai.base.usage_object_type | Type of the usage record | keyword |
| openai.base.user_id | Identifier of the user | keyword |


### Audio transcriptions

The `audio_transcriptions` data stream captures audio transcriptions usage metrics.

An example event for `audio_transcriptions` looks as following:

```json
{
    "openai": {
        "audio_transcriptions": {
            "seconds": 2
        },
        "base": {
            "start_time": "2024-11-04T00:00:00.000Z",
            "num_model_requests": 1,
            "project_id": "proj_dummy",
            "user_id": "user-dummy",
            "end_time": "2024-11-05T00:00:00.000Z",
            "model": "whisper-1",
            "api_key_id": "key_dummy",
            "usage_object_type": "organization.usage.audio_transcriptions.result"
        }
    },
    "@timestamp": "2024-11-04T00:00:00.000Z",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "openai.audio_transcriptions"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-28T21:56:24Z",
        "created": "2025-01-28T21:56:24.113Z",
        "kind": "metric",
        "dataset": "openai.audio_transcriptions"
    },
    "tags": [
        "forwarded",
        "openai-audio-transcriptions"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| openai.audio_transcriptions.seconds | Number of seconds processed | long | s |
| openai.base.api_key_id | Identifier for the API key used | keyword |  |
| openai.base.end_time | End timestamp of the usage bucket | date |  |
| openai.base.model | Name of the OpenAI model used | keyword |  |
| openai.base.num_model_requests | Number of requests made to the model | long |  |
| openai.base.project_id | Identifier of the project | keyword |  |
| openai.base.start_time | Start timestamp of the usage bucket | date |  |
| openai.base.usage_object_type | Type of the usage record | keyword |  |
| openai.base.user_id | Identifier of the user | keyword |  |


### Code interpreter sessions

The `code_interpreter_sessions` data stream captures code interpreter sessions usage metrics.

An example event for `code_interpreter_sessions` looks as following:

```json
{
    "openai": {
        "code_interpreter_sessions": {
            "sessions": 16
        },
        "base": {
            "start_time": "2024-09-04T00:00:00.000Z",
            "project_id": "",
            "end_time": "2024-09-05T00:00:00.000Z",
            "usage_object_type": "organization.usage.code_interpreter_sessions.<dummy>"
        }
    },
    "@timestamp": "2024-09-04T00:00:00.000Z",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "openai.code_interpreter_sessions"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-28T21:56:19Z",
        "created": "2025-01-28T21:56:17.099Z",
        "kind": "metric",
        "dataset": "openai.code_interpreter_sessions"
    },
    "tags": [
        "forwarded",
        "openai-code-interpreter-sessions"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| openai.base.end_time | End timestamp of the usage bucket | date |
| openai.base.project_id | Identifier of the project | keyword |
| openai.base.start_time | Start timestamp of the usage bucket | date |
| openai.base.usage_object_type | Type of the usage record | keyword |
| openai.code_interpreter_sessions.sessions | Number of code interpreter sessions | long |


### Completions

The `completions` data stream captures completions usage metrics.

An example event for `completions` looks as following:

```json
{
    "openai": {
        "completions": {
            "output_audio_tokens": 0,
            "batch": false,
            "input_audio_tokens": 0,
            "input_cached_tokens": 0,
            "input_tokens": 22,
            "output_tokens": 149
        },
        "base": {
            "start_time": "2025-01-27T00:00:00.000Z",
            "num_model_requests": 1,
            "project_id": "proj_dummy",
            "user_id": "user-dummy",
            "end_time": "2025-01-28T00:00:00.000Z",
            "model": "gpt-4o-mini-2024-07-18",
            "api_key_id": "key_dummy",
            "usage_object_type": "organization.usage.completions.result"
        }
    },
    "@timestamp": "2025-01-27T00:00:00.000Z",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "openai.completions"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-28T21:56:30Z",
        "created": "2025-01-28T21:56:29.346Z",
        "kind": "metric",
        "dataset": "openai.completions"
    },
    "tags": [
        "forwarded",
        "openai-completions"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| openai.base.api_key_id | Identifier for the API key used | keyword |
| openai.base.end_time | End timestamp of the usage bucket | date |
| openai.base.model | Name of the OpenAI model used | keyword |
| openai.base.num_model_requests | Number of requests made to the model | long |
| openai.base.project_id | Identifier of the project | keyword |
| openai.base.start_time | Start timestamp of the usage bucket | date |
| openai.base.usage_object_type | Type of the usage record | keyword |
| openai.base.user_id | Identifier of the user | keyword |
| openai.completions.batch | Whether the request was processed as a batch | boolean |
| openai.completions.input_audio_tokens | Number of audio input tokens used, including cached tokens | long |
| openai.completions.input_cached_tokens | Number of text input tokens that has been cached from previous requests. For customers subscribe to scale tier, this includes scale tier tokens | long |
| openai.completions.input_tokens | Number of text input tokens used, including cached tokens. For customers subscribe to scale tier, this includes scale tier tokens | long |
| openai.completions.output_audio_tokens | Number of audio output tokens used | long |
| openai.completions.output_tokens | Number of text output tokens used. For customers subscribe to scale tier, this includes scale tier tokens | long |


### Embeddings

The `embeddings` data stream captures embeddings usage metrics.

An example event for `embeddings` looks as following:

```json
{
    "openai": {
        "embeddings": {
            "input_tokens": 16
        },
        "base": {
            "start_time": "2024-09-04T00:00:00.000Z",
            "num_model_requests": 2,
            "project_id": "",
            "user_id": "user-dummy",
            "end_time": "2024-09-05T00:00:00.000Z",
            "model": "text-embedding-ada-002-v2",
            "api_key_id": "key_dummy",
            "usage_object_type": "organization.usage.embeddings.result"
        }
    },
    "@timestamp": "2024-09-04T00:00:00.000Z",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "openai.embeddings"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-28T21:56:19Z",
        "created": "2025-01-28T21:56:17.149Z",
        "kind": "metric",
        "dataset": "openai.embeddings"
    },
    "tags": [
        "forwarded",
        "openai-embeddings"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| openai.base.api_key_id | Identifier for the API key used | keyword |
| openai.base.end_time | End timestamp of the usage bucket | date |
| openai.base.model | Name of the OpenAI model used | keyword |
| openai.base.num_model_requests | Number of requests made to the model | long |
| openai.base.project_id | Identifier of the project | keyword |
| openai.base.start_time | Start timestamp of the usage bucket | date |
| openai.base.usage_object_type | Type of the usage record | keyword |
| openai.base.user_id | Identifier of the user | keyword |
| openai.embeddings.input_tokens | Number of input tokens used. | long |


### Images

The `images` data stream captures images usage metrics.

An example event for `images` looks as following:

```json
{
    "openai": {
        "images": {
            "images": 1,
            "size": "1024x1024",
            "source": "image.generation"
        },
        "base": {
            "start_time": "2024-09-04T00:00:00.000Z",
            "num_model_requests": 1,
            "project_id": "",
            "user_id": "user-dummy",
            "end_time": "2024-09-05T00:00:00.000Z",
            "model": "dall-e-3",
            "api_key_id": "key_dummy",
            "usage_object_type": "organization.usage.images.result"
        }
    },
    "@timestamp": "2024-09-04T00:00:00.000Z",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "openai.images"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-28T21:56:19Z",
        "created": "2025-01-28T21:56:17.758Z",
        "kind": "metric",
        "dataset": "openai.images"
    },
    "tags": [
        "forwarded",
        "openai-images"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| openai.base.api_key_id | Identifier for the API key used | keyword |
| openai.base.end_time | End timestamp of the usage bucket | date |
| openai.base.model | Name of the OpenAI model used | keyword |
| openai.base.num_model_requests | Number of requests made to the model | long |
| openai.base.project_id | Identifier of the project | keyword |
| openai.base.start_time | Start timestamp of the usage bucket | date |
| openai.base.usage_object_type | Type of the usage record | keyword |
| openai.base.user_id | Identifier of the user | keyword |
| openai.images.images | Number of images processed | long |
| openai.images.size | Image size (dimension of the generated image) | keyword |
| openai.images.source | Source of the grouped usage result, possible values are `image.generation`, `image.edit`, `image.variation` | keyword |


### Moderations

The `moderations` data stream captures moderations usage metrics.

An example event for `moderations` looks as following:

```json
{
    "openai": {
        "moderations": {
            "input_tokens": 16
        },
        "base": {
            "start_time": "2024-09-04T00:00:00.000Z",
            "num_model_requests": 2,
            "project_id": "",
            "user_id": "user-dummy",
            "end_time": "2024-09-05T00:00:00.000Z",
            "model": "text-moderation:2023-10-25",
            "api_key_id": "key_dummy",
            "usage_object_type": "organization.usage.moderations.result"
        }
    },
    "@timestamp": "2024-09-04T00:00:00.000Z",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "openai.moderations"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-28T21:56:19Z",
        "created": "2025-01-28T21:56:17.099Z",
        "kind": "metric",
        "dataset": "openai.moderations"
    },
    "tags": [
        "forwarded",
        "openai-moderations"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| openai.base.api_key_id | Identifier for the API key used | keyword |
| openai.base.end_time | End timestamp of the usage bucket | date |
| openai.base.model | Name of the OpenAI model used | keyword |
| openai.base.num_model_requests | Number of requests made to the model | long |
| openai.base.project_id | Identifier of the project | keyword |
| openai.base.start_time | Start timestamp of the usage bucket | date |
| openai.base.usage_object_type | Type of the usage record | keyword |
| openai.base.user_id | Identifier of the user | keyword |
| openai.moderations.input_tokens | Number of input tokens used. | long |


### Vector stores

The `vector_stores` data stream captures vector stores usage metrics.

An example event for `vector_stores` looks as following:

```json
{
    "openai": {
        "vector_stores": {
            "usage_bytes": 16
        },
        "base": {
            "start_time": "2024-09-04T00:00:00.000Z",
            "project_id": "",
            "end_time": "2024-09-05T00:00:00.000Z",
            "usage_object_type": "organization.usage.vector_stores.<dummy>"
        }
    },
    "@timestamp": "2024-09-04T00:00:00.000Z",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "openai.vector_stores"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-28T21:56:19Z",
        "created": "2025-01-28T21:56:17.099Z",
        "kind": "metric",
        "dataset": "openai.vector_stores"
    },
    "tags": [
        "forwarded",
        "openai-vector-stores"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| openai.base.end_time | End timestamp of the usage bucket | date |  |
| openai.base.project_id | Identifier of the project | keyword |  |
| openai.base.start_time | Start timestamp of the usage bucket | date |  |
| openai.base.usage_object_type | Type of the usage record | keyword |  |
| openai.vector_stores.usage_bytes | Vector stores usage in bytes | long | byte |

