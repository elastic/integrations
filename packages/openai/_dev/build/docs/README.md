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
