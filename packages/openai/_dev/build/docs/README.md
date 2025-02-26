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

By default, the OpenAI integration fetches metrics with a bucket width of 1 day (`1d`), which means metrics are aggregated by day. metrics are collected from the initial start time until the current time, excluding the current bucket since it is incomplete. So, based on configured bucket width, the integration collects metrics from the initial start time until the current time minus the bucket width.

## Logs reference

**ECS Field Reference**

Refer to this [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

### Audio speeches

The `audio_speeches` data stream captures audio speeches usage metrics.

{{event "audio_speeches"}}

{{fields "audio_speeches"}}

### Audio transcriptions

The `audio_transcriptions` data stream captures audio transcriptions usage metrics.

{{event "audio_transcriptions"}}

{{fields "audio_transcriptions"}}

### Code interpreter sessions

The `code_interpreter_sessions` data stream captures code interpreter sessions usage metrics.

{{event "code_interpreter_sessions"}}

{{fields "code_interpreter_sessions"}}

### Completions

The `completions` data stream captures completions usage metrics.

{{event "completions"}}

{{fields "completions"}}

### Embeddings

The `embeddings` data stream captures embeddings usage metrics.

{{event "embeddings"}}

{{fields "embeddings"}}

### Images

The `images` data stream captures images usage metrics.

{{event "images"}}

{{fields "images"}}

### Moderations

The `moderations` data stream captures moderations usage metrics.

{{event "moderations"}}

{{fields "moderations"}}

### Vector stores

The `vector_stores` data stream captures vector stores usage metrics.

{{event "vector_stores"}}

{{fields "vector_stores"}}
