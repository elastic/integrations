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

There are two advanced configuration options for the OpenAI integration: "Initial interval" and "Bucket width".

### Initial interval

- Controls the historical data collection window at startup
- Default value: 24 hours (`24h`)
- Purpose: Loads historical context when you first set up the integration

### Bucket width

- Controls the time-based aggregation of metrics (e.g., [bucket_width](https://platform.openai.com/docs/api-reference/usage/completions#usage-completions-bucket_width))
- Default: `1m` (1 minute)
- Options: `1m`, `1h`, `1d`
- Affects API request frequency and data resolution

#### Impact on data resolution

Granularity relationship: `1m` > `1h` > `1d`
- `1m` buckets provide the highest resolution metrics, with data arriving nearly in real-time (1-minute delay)
- `1h` buckets aggregate 60-minute intervals, with data arriving less frequently (1-hour delay)
- `1d` buckets consolidate full 24-hour periods, with data arriving daily (24-hour delay)

#### Storage considerations

Bucket width choice affects storage usage and data resolution:
- `1m`: Maximum granularity, higher storage needs
- `1h`: Aggregates 60 one-minute intervals
- `1d`: Most efficient storage, suitable for long-term analysis

Example: For 100 API calls to a particular model per hour:
- `1m` buckets: Up to 100 documents
- `1h` buckets: 1 aggregated document
- `1d` buckets: 1 daily document

#### API request impact

"Bucket width" and "Initial interval" directly affect API request frequency. Here's the technical breakdown:

OpenAI Usage API returns different numbers of buckets based on the bucket width:
- 1-minute buckets: 60 buckets per API call
- 1-hour buckets: 24 buckets per API call
- 1-day buckets: 7 buckets per API call

Formula for API calls:
1. Hours in initial interval × (60 minutes / bucket size) = Total buckets needed
2. Total buckets / buckets per API call = API calls per data stream
3. Total API calls = API calls per data stream × 8 data streams

Technical calculation example with 6-month initial interval and 1-minute buckets:
- "Initial interval" conversion: 6 months = (6 × 30 × 24) = 4,320 hours
- Total buckets needed: 4,320 hours × 60 minutes = 259,200 buckets
- API calls per stream: 259,200 / 60 = 4,320 calls
- Total API calls across 8 streams: 4,320 × 8 = 34,560 API calls

Making 34,560 API calls in a brief period will likely trigger OpenAI's rate limits, resulting in API errors. When using a 1-minute bucket width, it's strongly recommended to set the "Initial interval" to a shorter duration - optimally 1 day - to ensure smooth performance. While our extensive testing demonstrates excellent results with a 6-month initial interval paired with a 1-day bucket width, the same level of success isn't achievable with 1-minute or 1-hour bucket widths due to OpenAI's API rate limitations. For optimal results when collecting historical data over extended periods, implementing 1-day bucket widths proves to be the most effective approach, balancing data granularity with API constraints.

### Collection process

With default settings (Interval: 5m, Bucket width: 1m, Initial interval: 24h), the OpenAI integration follows this collection pattern:

1. Starts collection from (current_time - initial_interval)
2. Collects data up to (current_time - bucket_width)
3. Excludes incomplete current bucket for data accuracy and wait for bucket completion
4. Runs every 5 minutes by default (configurable)
5. From second collection, start from end of previous bucket timestamp and collect up to (current_time - bucket_width)

#### Example timeline

With default settings (Interval: 5m, Bucket width: 1m, Initial interval: 24h):

1. Integration starts at 10:00 AM
2. Collects data from 10:00 AM previous day
3. Continues until 9:59 AM current day
4. Next collection starts at 10:05 AM from the 10:00 AM bucket to 10:04 AM as the "Interval" is 5 minutes.

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
