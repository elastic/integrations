# OpenAI

The OpenAI integration allows you to monitor OpenAI API usage metrics and collect organization audit logs. OpenAI is an AI research and deployment company that offers [API platform](https://openai.com/api) for their industry-leading foundation models.

With the OpenAI integration, you can track API usage metrics across their models, as well as for vector store and code interpreter. You can also collect audit logs from the OpenAI platform to monitor user actions, API key lifecycle events, and organization configuration changes. You will use Kibana to visualize your data, create alerts if usage limits are approaching, view metrics when you troubleshoot issues, and analyze audit events for security and compliance. For example, you can track token usage and API calls per model, as well as login attempts, API key creation/deletion, and role assignments.

## Data collection

The OpenAI integration leverages the following OpenAI APIs for data collection:

- **Usage API**: The [OpenAI Usage API](https://platform.openai.com/docs/api-reference/usage) delivers comprehensive insights into your API activity, helping you understand and optimize your organization's OpenAI API usage.

- **Audit Logs API**: The [OpenAI Audit Logs API](https://platform.openai.com/docs/api-reference/audit-logs) collects organization audit logs, providing visibility into user actions, API key lifecycle events, login attempts, role assignments, and other platform activity for security oversight and compliance.

- **Rate Limits API**: The [OpenAI Rate Limits API](https://platform.openai.com/docs/api-reference/project-rate-limits) collects the configured per-project, per-model rate limits (requests, tokens and images per minute, plus daily and batch limits). Combined with usage data, this lets you monitor how close each project is to being throttled.

## Data streams

The OpenAI integration collects the following data streams:

- `audit`: Collects organization audit logs.
- `audio_speeches`: Collects audio speeches usage metrics.
- `audio_transcriptions`: Collects audio transcriptions usage metrics.
- `code_interpreter_sessions`: Collects code interpreter sessions usage metrics.
- `completions`: Collects completions usage metrics.
- `embeddings`: Collects embeddings usage metrics.
- `images`: Collects images usage metrics.
- `moderations`: Collects moderations usage metrics.
- `rate_limits`: Collects per-project, per-model rate limits.
- `vector_stores`: Collects vector stores usage metrics.

> Note: Users can view OpenAI metrics in the `logs-*` index pattern using Kibana Discover.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.

You need an OpenAI account with a valid [Admin key](https://platform.openai.com/settings/organization/admin-keys) for programmatic access to the [OpenAI Usage API](https://platform.openai.com/docs/api-reference/usage) and [OpenAI Audit Logs API](https://platform.openai.com/docs/api-reference/audit-logs). To fetch audit logs, you must enable audit logging on the OpenAI platform in your organization settings under Data controls > Data retention. Audit logs also require Organization Owner permissions.

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/starting-with-the-elasticsearch-platform-and-its-solutions/current/getting-started-observability.html) guide.

### Generate an Admin key

To generate an Admin key, please generate a key or use an existing one from the [Admin keys](https://platform.openai.com/settings/organization/admin-keys) page. Use the Admin key to configure the OpenAI integration.

## Collection behavior

Among the configuration options for the OpenAI integration, the following settings are particularly relevant: "Initial interval" and "Bucket width" for usage metrics, and "Initial interval" and "Interval" for audit logs.

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

## Rate limit headroom

The `rate_limits` data stream collects the per-project, per-model limits OpenAI enforces (requests, tokens and images per minute, plus daily and batch limits). On its own a limit is just a number; it becomes actionable when compared against actual usage. The OpenAI dashboard ships two **Rate limit headroom** panels — one broken down per project and model, and an org-wide rollup by model across all active projects — plus a prebuilt **[OpenAI] Rate limit headroom low** threshold alert that do exactly this.

### How the comparison works

Limits and usage are joined on the exact `project_id` and `model` strings. The Usage API reports dated model snapshots (for example `gpt-4o-mini-2024-07-18`), and the Rate Limits API contains that same snapshot string as its own row, so an exact-string join matches without any normalization.

Utilization is computed as `usage / limit`, where usage is the **peak** value over the look-back window:

1. Usage is summed per project, model and 1-minute bucket.
2. The peak (maximum) minute in the window is taken.
3. That peak is divided by the configured limit.

Only matching units are compared:

- tokens ↔ tokens per minute (TPM)
- requests ↔ requests per minute (RPM)
- images ↔ images per minute

Audio is deliberately left out. OpenAI enforces an audio limit (`max_audio_megabytes_per_1_minute`), but the Usage API reports audio only in seconds (`audio_transcriptions`) and characters (`audio_speeches`) — never in megabytes — so there is no comparable usage figure to divide by the limit. Audio therefore stays usage-only until a megabyte-denominated usage metric is available. Usage measured in characters or sessions likewise has no corresponding rate limit and stays usage-only.

> **Hard requirement:** the peak 1-minute calculation depends on the usage streams (`completions`, `embeddings`, `moderations`, ...) running with **`bucket_width: 1m`**. This is the default, but the value is user-editable — if it is changed to `1h` or `1d`, the headroom numbers will be wrong because a wider bucket smears per-minute peaks.

> **Note on aggregation:** OpenAI returns identical limits for both the model family (`gpt-4o-mini`) and its dated snapshot (`gpt-4o-mini-2024-07-18`). Because these duplicate the same capacity, every headroom aggregation is driven off the usage side of the join (usage matches exactly one row). Do not sum limit rows independently, or capacity will be double-counted. Family rows with no matching usage appear as 0%-utilization rows.

### Org-wide rollup by model

The **Rate limit headroom - by model (org-wide)** panel answers a different question: "how is model X doing across the whole org?" It drops the `project_id` breakdown and aggregates by model alone — usage is summed across all active projects per 1-minute bucket, and the peak minute is taken just as in the per-project panel.

OpenAI enforces rate limits **per project**, so there is no single org-wide throttle boundary to divide against. The rollup therefore presents its limit columns as a **synthetic aggregate** (the sum of the per-project limits) and labels both the limit and utilization columns accordingly (`limit (aggregate)`, `utilization (approx.)`). Use these for relative comparison and trend-spotting across models; the exact throttle distance for any individual project still lives in the per-project panel and the alert.

### Alert

The **[OpenAI] Rate limit headroom low** rule fires when peak 1-minute token usage (TPM) reaches 80% or more of the configured limit for a project and model. It is grouped by `project_id::model`, evaluates over a 15-minute window every 5 minutes, and reflects sustained utilization rather than a single real-time spike.

To tune the threshold, edit the `WHERE tpm_utilization >= 0.8` line in the rule's ES|QL query.

## Metrics reference

**ECS Field Reference**

Refer to this [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

### Audit logs

The `audit` data stream captures organization audit logs.

{{event "audit"}}

{{fields "audit"}}

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

### Rate limits

The `rate_limits` data stream captures per-project, per-model rate limits.

{{event "rate_limits"}}

{{fields "rate_limits"}}

### Vector stores

The `vector_stores` data stream captures vector stores usage metrics.

{{event "vector_stores"}}

{{fields "vector_stores"}}
