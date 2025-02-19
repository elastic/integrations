# OpenAI

The OpenAI integration allows you to monitor OpenAI API usage metrics. OpenAI is an AI research and deployment company that offers [API platform](https://openai.com/api) for their industry-leading foundation models.

With the OpenAI integration, you can track API usage metrics across their models, as well as for vector store and code interpreter. You will use Kibana to visualize your data, create alerts if usage limits are approaching, and view metrics when you troubleshoot issues. For example, you can track token usage and API calls per model.

## Data collection

The OpenAI integration leverages the [OpenAI Usage API](https://platform.openai.com/docs/api-reference/usage) to collect detailed usage metrics. The Usage API delivers comprehensive insights into your API activity, helping you understand and optimize your organization's OpenAI API usage.

## Data streams

The OpenAI integration collects the following logs data streams:

- `audio_speeches`: Collects audio speeches usage metrics.
- `audio_transcriptions`: Collects audio transcriptions usage metrics.
- `code_interpreter_sessions`: Collects code interpreter sessions usage metrics.
- `completions`: Collects completions usage metrics.
- `embeddings`: Collects embeddings usage metrics.
- `images`: Collects images usage metrics.
- `moderations`: Collects moderations usage metrics.
- `vector_stores`: Collects vector stores usage metrics.

See more details for data streams in the [Logs](#logs-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.

You need an OpenAI account with a valid [Admin key](https://platform.openai.com/settings/organization/admin-keys) for programmatic access to [OpenAI Usage API](https://platform.openai.com/docs/api-reference/usage).

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/starting-with-the-elasticsearch-platform-and-its-solutions/current/getting-started-observability.html) guide.

### Generate an Admin key

To generate an Admin key, please generate a key or use an existing one from the [Admin keys](https://platform.openai.com/settings/organization/admin-keys) page. Use the Admin key to configure the OpenAI integration.

## Collection behavior

By default, the OpenAI integration fetches metrics with a bucket width of 1 day (`1d`), which means metrics are aggregated by day. Metrics are collected from the initial start time until the current time, excluding the current bucket since it is incomplete. So, based on configured bucket width, the integration collects metrics from the initial start time until the current time minus the bucket width.

## Logs reference

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

