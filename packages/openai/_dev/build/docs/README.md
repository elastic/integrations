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

Among the configuration options for the OpenAI integration, the following settings are particularly relevant: "Initial interval", "Bucket width" and "Finalization grace period" for usage metrics, and "Initial interval" and "Interval" for audit logs.

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

### Finalization grace period

OpenAI's Usage API does not finalize a per-minute bucket the moment it ends — a bucket's token and request counts keep climbing for several minutes afterward as late usage is accounted for. To avoid ingesting these partial, still-changing counts, each of the six token- and request-based usage data streams — `completions`, `embeddings`, `moderations`, `images`, `audio_speeches`, and `audio_transcriptions` — waits a configurable **finalization grace period** before treating a bucket as final. (The `code_interpreter_sessions` and `vector_stores` streams do not report token or request counts, do not feed the rate limit headroom dashboard, and have no grace setting.)

> **Note:** This finalization lag is *observed* behavior, not a documented OpenAI guarantee. The Usage API reference does not specify a revision window or finalization delay, so the recommended `15m` value below is an empirically chosen buffer, not a figure published by OpenAI; the lag may change without notice.

- Controls how long to wait after a bucket's end time before the bucket is ingested
- Default value: `0s`. Buckets are ingested as soon as they are read, with no added delay. This keeps usage data fresh and is the least disruptive setting for existing deployments, but it can undercount usage during heavy bursts, because OpenAI is still revising a bucket's counts for several minutes after its end time and the bucket is read before those counts settle.
- Recommended for accurate counts: `15m`. Setting the grace to 15 minutes gives each per-minute bucket time to finalize before it is ingested, so the stored token and request counts match what OpenAI eventually reports. Choose this when accurate usage and rate limit headroom matter more than freshness — for example, when reconciling against the OpenAI dashboard or driving the headroom alert.
- How it works: buckets whose end time is younger than the grace period are skipped and re-fetched on a later poll, so only finalized counts are stored.
- Trade-off: a longer grace period is safer against undercounting (heavy bursts take OpenAI longer to finalize) but delays when usage first appears in Elasticsearch by up to the grace period. With `15m`, these six usage data streams — and the rate limit headroom panels and alert that read from them — trail real time by roughly 15 minutes. With the default `0s` there is no added lag, but the most recent minutes can be permanently undercounted: each bucket is ingested as soon as its minute closes — before OpenAI finishes revising it — and is not re-read afterward, so later upward revisions are never reflected.
- Where to change it: use the **Finalization grace period** setting for each of these six usage data streams.

> If usage metrics read lower than the OpenAI dashboard under high-volume bursts, increase the finalization grace period — `15m` is recommended. If you need the freshest possible dashboards and can tolerate undercounting the most recent minutes, keep the default `0s`.

#### Known limitation: residual undercount under high-volume bursts

The finalization grace period eliminates the bulk of the undercount, but it cannot fully remove it. OpenAI's per-minute usage finalization is non-monotonic: during high-volume bursts a bucket's counts can continue to be revised upward for hours — beyond any fixed grace period. Because each bucket is ingested once and not re-fetched after it is treated as final, those late revisions are not reflected, so a small residual undercount (observed at a few percent of a single minute's volume) may remain for the busiest buckets. This does not affect the headroom dashboard's ability to flag over-limit conditions, since the gap is small relative to the limit. If you require usage counts that exactly match the OpenAI dashboard, prefer a larger bucket width (`1h` or `1d`), which OpenAI finalizes more stably than `1m`.

### Collection process

With default settings (Interval: `5m`, Bucket width: `1m`, Initial interval: `24h`), the OpenAI integration follows this collection pattern:

1. Starts collection from (current_time - initial_interval)
2. Collects data up to (current_time - finalization_grace)
3. Skips buckets OpenAI has not yet finalized (those whose end time is within the finalization grace period) and re-fetches them on a later poll once they are final
4. Runs every 5 minutes by default (configurable)
5. From the second collection onward, resumes from the oldest not-yet-finalized bucket so late-arriving counts are captured without duplication

#### Example timeline

With these settings (Interval: `5m`, Bucket width: `1m`, Initial interval: `24h`) and a finalization grace period of `15m` (the recommended setting for accurate counts):

The integration starts at 10:00 AM and collects data from 10:00 AM the previous day up to 9:45 AM the current day — the most recent 15 minutes are still finalizing and are skipped. The next collection starts at 10:05 AM and resumes from the 9:45 AM bucket, re-fetching any of those buckets that have since been finalized and continuing up to 9:50 AM.

With the default grace period of `0s`, collection instead runs all the way up to the current time and no buckets are skipped — each bucket is ingested as soon as its minute closes. Those buckets appear immediately, but because they are read before OpenAI finishes revising them and are not re-read once ingested, any later upward revisions are not reflected and the counts can stay undercounted.

## Rate limit headroom

The `rate_limits` data stream collects the per-project, per-model limits OpenAI enforces (requests, tokens and images per minute, plus daily and batch limits). On its own a limit is just a number; it becomes actionable when compared against actual usage. The OpenAI dashboard ships two **Rate limit headroom** panels — one broken down per project and model, and an org-wide rollup by model across all active projects — plus a prebuilt **[OpenAI] Rate limit headroom low** threshold alert that do exactly this.

### How the comparison works

Limits and usage are joined on the exact `project_id`, but the `model` is **normalized** before joining: a trailing dated snapshot suffix (`-YYYY-MM-DD`) is stripped from both sides so that each model collapses to its base family. The Usage API reports per dated snapshot (for example `gpt-image-1-2025-04-23`, `omni-moderation-2024-09-26`), while the Rate Limits API often lists only the base family name (`gpt-image-1`, `omni-moderation`). Without normalization the dated usage row would find no matching limit and be dropped from the join, so the queries apply `REPLACE(<model>, "-[0-9]{4}-[0-9]{2}-[0-9]{2}$", "")` to align dated usage snapshots with base rate-limit names. When the Rate Limits API does report the dated snapshot as its own row, normalization simply collapses it onto the same base key as the family row.

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

> **Note on aggregation:** OpenAI returns identical limits for both the model family (`gpt-4o-mini`) and its dated snapshot (`gpt-4o-mini-2024-07-18`). After normalization both collapse onto the same base `model` key, so the per-minute aggregation takes the limit as `MAX(...)` over the rows in each `project_id`/`model`/minute bucket. `MAX` (not `SUM`) is what prevents the duplicated family and snapshot limit rows from double-counting capacity — they report the same number, so the max equals either one. A base model that has a limit but no usage in the window appears as a 0%-utilization row.

### Org-wide rollup by model

The **Rate limit headroom - by model (org-wide)** panel answers a different question: "how is model X doing across the whole org?" It drops the `project_id` breakdown and aggregates by model alone. For each project it first takes that project's peak 1-minute usage over the window (exactly as the per-project panel does), then sums those per-project peaks into the org-wide usage figure.

Because each project's peak can fall in a different minute, this sum-of-peaks is an **indicative upper bound** rather than a true simultaneous org-wide peak — it assumes every project peaked at once, so it can read higher than the actual combined load in any single minute. This is intentional: it keeps the usage rollup aligned with the limit rollup (see below) and errs toward flagging pressure rather than hiding it.

OpenAI enforces rate limits **per project**, so there is no single org-wide throttle boundary to divide against. The rollup therefore presents its limit columns as a **synthetic aggregate** (each project's limit stabilized as the max over the window, then summed across projects) and labels both the limit and utilization columns accordingly (`limit (aggregate)`, `utilization (approx.)`). Use these for relative comparison and trend-spotting across models; the exact throttle distance for any individual project still lives in the per-project panel and the alert.

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
