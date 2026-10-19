{{- generatedHeader }}
# WhoisFreaks Integration for Elastic

## Overview

The WhoisFreaks integration collects data published by [WhoisFreaks](https://whoisfreaks.com/)
and indexes it into Elasticsearch:

- The daily gTLD and ccTLD newly registered domain ("domainer") feeds, with and
  without WHOIS records. These documents are enrichment data
  (`event.kind: enrichment`) under `whoisfreaks.*`: a newly registered domain is
  a risk signal, not an indicator of compromise, so these documents are not
  typed as threat indicators.
- The daily malware, phishing, and spam domain threat feeds. These documents
  are threat indicators (`event.category: threat`, `event.type: indicator`) with
  the domain in `threat.indicator.url.domain` and `threat.indicator.name`, and
  they are expired with an Elastic latest transform.

### Compatibility

This integration requires a WhoisFreaks account and an API key from the WhoisFreaks
billing dashboard, with:

- an active **Domainer Subscription** for the `nrd_with_whois` and `nrd_without_whois`
  data streams, and
- an active **Threat Feed subscription** for the `threat_feed_malware`,
  `threat_feed_phishing`, and `threat_feed_spam` data streams.

### How it works

The integration contains five Elastic Agent CEL inputs. Every WhoisFreaks stream
request requires a `date` query parameter (`yyyy-MM-dd`), so all five inputs work the
same way:

1. On each poll, call the public WhoisFreaks **status endpoint** (`/v3.4/status`, no
   API key needed) and read that feed's `last_update` and `available_from` dates:
   `newly.gtld` and `newly.cctld` for the two newly registered domain streams, and
   `threat_feed.malware`, `threat_feed.phishing`, or `threat_feed.spam` for the
   threat feeds.
2. Pick the file date: the feed's `last_update` by default, or the configured
   **File Date** if one is set (see [File Date](#file-date)). Every stream request
   carries this `date` parameter; only the status endpoint is called without one.
3. Compare it with the last file date already ingested for that feed, which is kept
   in the input cursor. If it is not newer, the poll ends after the status call, so
   the default `1h` **Interval** never re-pages a daily file.
4. Otherwise, page through the stream endpoint with `date`, `limit`, and a growing
   `offset` until a page comes back short, then record the date as ingested.

Every column of every stream response is kept. CSV rows are mapped by the column
names in the response's header row (the header of the first page is reused for later
pages that do not repeat it), so a reordered or newly added column is indexed rather
than dropped. Only empty cells are left out.

Every document carries the file date it came from in `whoisfreaks.file_date`. All
inputs emit one document per row or domain.

#### File Date

**File Date** is optional on every data stream. Leave it empty (recommended) to always
fetch the latest file reported by the status endpoint. When it is set, the input:

- Checks that the value is a real calendar date in `yyyy-MM-dd` format.
- Checks against the status endpoint that it falls within the feed's
  `available_from`..`last_update` range, inclusive (for the newly registered domain
  streams, separately for gTLD and ccTLD).
- Fetches a valid date once, and then continues with the latest file. Later polls
  follow the latest file even while the setting stays filled in. Changing the value
  fetches the new date once.
- If either check fails, indexes one error document that names the configured date
  and the allowed range, makes no stream request for that date, and continues with
  the latest file. If the date is valid for only one of gTLD/ccTLD, it is fetched for
  that feed.
- Tracks the pinned file separately from the latest ingested file, so fetching a
  historical file never causes the latest file to be fetched again.

#### Error handling

Every status and stream request is checked. Failures are indexed as a single error
document with `error.code` and an `error.message` that contains the method, the URL
(the API key is always removed), the HTTP status, and the WhoisFreaks `error` and
`message` text when the response is JSON.

- **Server, timeout, rate-limit, and network errors** (5xx, 408, 429, transport
  failures): the cursor is kept, so the next poll retries the same page.
- **Authentication errors** (401, 403, and the HTTP 400 `Api Access Exception` that
  WhoisFreaks returns for a missing or invalid API key): reported with a hint to check
  the API key and the Domainer or Threat Feed subscription; the cursor is kept and the
  next poll retries, so no file is skipped.
- **Other client errors** (for example 400 or 404): the file date is recorded as done
  for that feed so the input does not retry it forever; the newly registered domain
  streams move on to the other TLD type's pending file.
- **Status endpoint failures** (non-2xx, malformed JSON, missing feed, or a
  `Not Available` value): reported as an error document and no stream request is made.

#### `nrd_with_whois`

The `nrd_with_whois` data stream uses the Elastic Agent **CEL input** to:

1. Query the public WhoisFreaks **status endpoint** (`/v3.4/status`) and read
   `newly.gtld.last_update` and `newly.cctld.last_update`. These are the dates
   of the latest available gTLD and ccTLD WHOIS files.
2. Compare each date against the last file of that type already ingested, which
   is tracked in two independent cursors in the input's persistent state.
3. For each feed with a newer date, page through the corresponding stream
   endpoint (`/gtld` or `/cctld`) with `whois=true`, `date`, `limit`, and a
   growing `offset` as query parameters, and the API key sent as the
   `apiKey` query parameter. Each page is parsed as a CSV with a header.
4. Emit each CSV row, tagged with `tld_type` (`gtld` or `cctld`), as a JSON
   `message` and advance that feed's cursor to the ingested date once paging for
   that feed completes. If a page request fails with a server, authentication, or
   rate-limit error, the cursor is kept, so the next poll resumes that page instead
   of skipping the day's file. Other client errors (for example an invalid
   **File Date**) are reported as an error event, that feed's file for the date is
   marked as done, and the input moves on to the other feed's pending file.
5. Run the result through an ingest pipeline that preserves the raw record in
   `event.original`, parses it into `whoisfreaks.*`, sets `@timestamp`, parses the
   WHOIS dates, derives `whoisfreaks.days_until_expiry` and
   `whoisfreaks.is_newly_registered`, and fingerprints `tld_type` +
   `domain_name` + `query_time` into the document `_id` for idempotent
   re-polling.

Each daily file holds only that day's newly registered domains, so no day is skipped
after a gap (for example an agent outage or an error that lasts more than a day). When
the last ingested date is older than the status `last_update`, the input fetches the
following days one at a time, starting from the day after the last ingested date (or
from `available_from` when that is later), until it reaches `last_update`. On the
first run, the input starts from the current `last_update`. To load an older day, set
**File Date** to it, wait for it to be ingested, and then clear the setting again.

#### `nrd_without_whois`

The `nrd_without_whois` data stream follows the same daily status-driven pattern,
but it requests the stream with `whois=false`. This endpoint returns the domain
names as a plain newline-delimited list rather than a WHOIS CSV. The input:

1. Calls the public status API to discover the latest gTLD and ccTLD file dates.
2. Switches into the `gtld` or `cctld` paging mode only when that feed's date
   is newer than the last ingested value.
3. Splits the response body on `\n`, drops blank lines, and emits one event per
   non-empty domain entry with `whoisfreaks.domain_name`, the file date as
   `whoisfreaks.query_time`, and the matching `whoisfreaks.tld_type` tag.
4. Keeps the same cursor-based idempotency model as the WHOIS feed so it does
   not re-ingest identical daily snapshots.

Like the WHOIS feed, it uses a `1h` default **Interval**, catches up missed days the
same way, and polls without a new file only call the public status endpoint. Because
this feed has no per-domain timestamp, `whoisfreaks.query_time` (and `@timestamp`) is
the file date at 00:00:00 UTC.

#### Threat feeds: `threat_feed_malware`, `threat_feed_phishing`, `threat_feed_spam`

The three threat feeds are daily snapshot endpoints under the WhoisFreaks
v3.4 threat-feed API. Each input:

1. Reads `threat_feed.<type>.last_update` from the status endpoint (or uses the
   validated **File Date**) and, when that date is new, requests the feed endpoint
   for the relevant category (`malware`, `phishing`, or `spam`) with `date`, paging
   with `limit` and a growing `offset` until a page comes back short.
2. Emit each CSV row as the raw `message`, which the ingest pipeline preserves
   in `event.original` and parses by column name using the feed's header row.
   `domain`, `first_seen`, and `last_seen` populate the ECS indicator fields, and
   every other column (including any new one) is kept under
   `whoisfreaks.threat_feed.<column>`.
3. Emit one event per row with ECS threat fields (for example, `threat.indicator.type`
   and the feed-specific metadata).
4. Index upstream non-200 responses as error documents with `error.code` and
   `error.message` set rather than as threat indicators.

Each row is fingerprinted on `threat.indicator.url.domain` + `threat.indicator.last_seen`
+ `whoisfreaks.file_date` into the document `_id`, so re-fetching the same file never
duplicates documents. The latest transform keeps one document per domain: the copy
from the newest daily file (by `whoisfreaks.file_date`). Rows of a file fetched once
through **File Date** are flagged with `whoisfreaks.pinned_file: true`: they are kept
in the source data stream as history but are excluded from the latest (active)
indicator index, so a historical file never replaces or expires the indicators of
the newest file. Indicators are expired as described in
[Expiration of Indicators of Compromise (IOCs)](#expiration-of-indicators-of-compromise-iocs).

#### Replacing indicators from the previous file

Each threat feed file is a full daily snapshot. The **Replace indicators from the
previous file** setting (enabled by default) controls what happens to indicators
that a newer file no longer lists:

- **Enabled:** an indicator stays active until the next daily file is due (its file
  date plus 2 days, at 00:00 UTC), or until **IOC Expiration Duration** passes after
  `last_seen`, whichever comes first. Indicators repeated in the newest file get a
  later expiration from that file and stay active. Indicators missing from it are
  removed from the latest (active) indicator index automatically once the previous
  file's expiration passes, a few hours after the newest file is ingested. If no
  newer file is ingested (for example, during a long agent outage), the indicators
  from the last file also expire at that time.
- **Disabled:** indicators stay active until **IOC Expiration Duration** passes after
  `last_seen`, even if a newer file no longer lists them.

Elastic Agent cannot delete documents directly, so removal goes through the latest
transform's retention policy. The raw documents in the source data stream are removed
by its ILM policy.
If **IOC Expiration Duration** cannot be parsed, the default of `90d` is used and the
documents are tagged `invalid_ioc_expiration_duration`.


## What data does this integration collect?
The WhoisFreaks integration collects log messages of the following types:
* Domain WHOIS records for newly registered gTLDs and ccTLDs (with and without WHOIS enrichment).
* Malware, spam, and phishing domain threat indicators from the WhoisFreaks threat feeds.

### Supported use cases

* Domain portfolio management (expiration tracking).
* Threat intelligence / brand protection (newly registered domain
  monitoring, registrar/name-server pivoting).
* Registrar and TLD analytics.

## What do I need to use this integration?

* Elastic Agent.
* A WhoisFreaks account and API key with a Domainer Subscription (newly registered
  domain streams) and a Threat Feed subscription (threat feed streams).
* This integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview)
  for the threat feeds. For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup)
  setup and requirements.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

### Set up steps in WhoisFreaks

1. Sign in to the WhoisFreaks billing dashboard and confirm an active
   Domainer Subscription (for the newly registered domain streams) and Threat Feed
   subscription (for the threat feed streams).
2. Copy your API key from the dashboard.

#### Vendor resources
- [WhoisFreaks Newly Registered Domains API docs](https://whoisfreaks.com/documentation/newly-registered-domains)
- [WhoisFreaks documentation home](https://whoisfreaks.com/documentation)

### Set up steps in Kibana

1. Add the WhoisFreaks integration to an Agent policy.
2. Paste your API key in the integration-level **API Key** setting.
3. For each data stream, confirm the base **URL** (for the threat feeds this setting
   is under **Advanced options**). The defaults are already filled in:
   - `nrd_with_whois` and `nrd_without_whois`: the base domainer stream endpoint
     `https://files.whoisfreaks.com/v3.3/stream/domainer`, without the
     `gtld`/`cctld` suffix or query string.
   - `threat_feed_malware`, `threat_feed_phishing`, `threat_feed_spam`:
     `https://files.whoisfreaks.com/v3.4/stream/threat-feed/{malware,phishing,spam}`.
4. Leave **File Date** empty to always fetch the latest published file, or set a
   `yyyy-MM-dd` value within the feed's available range to fetch one historical file
   (see [File Date](#file-date)). Keep each stream's **Interval** at its default, and adjust
   **IOC Expiration Duration** (default `90d`) to control how long threat
   indicators stay active after they were last seen. Leave **Replace indicators from
   the previous file** enabled to keep only the indicators of the newest daily file
   active (see [Replacing indicators from the previous file](#replacing-indicators-from-the-previous-file)).
5. Save the integration and confirm the Agent starts collecting data.

### Validation

Open Discover and validate each stream independently:

- `logs-ti_whoisfreaks.nrd_with_whois-*` for WHOIS-rich gTLD/ccTLD records.
- `logs-ti_whoisfreaks.nrd_without_whois-*` for daily domain-only records.
- `logs-ti_whoisfreaks.threat_feed_malware-*`,
  `logs-ti_whoisfreaks.threat_feed_phishing-*`, and
  `logs-ti_whoisfreaks.threat_feed_spam-*` for the three threat indicators.

Each stream should show documents with a populated `whoisfreaks.domain_name` or
threat indicator fields and a valid `@timestamp`.

Check that the threat feed transforms are healthy:

1. In Kibana, navigate to **Management** > **Stack Management**.
2. Under **Data**, select **Transforms**.
3. In the search bar, type **whoisfreaks**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Troubleshooting

- No data is being collected: confirm the API key and the Domainer or Threat Feed subscription are valid; check `error.code` and `error.message` on error documents for the upstream HTTP status.
- `Please provide the date parameter` or `outside the available range` errors: check **File Date**. It must be `yyyy-MM-dd` and within the range that the status endpoint reports for that feed; leave it empty to follow the latest file.
- An upstream API failure (non-200 response) on any of the five data streams is indexed as a single document with `error.code` and `error.message` populated and no `event.category`, `event.type`, or `threat.*` fields set, so it is not mistaken for a normal indicator or WHOIS record. Search for them with the KQL query `data_stream.dataset: ti_whoisfreaks.* AND error.message: *`.
- Records that fail to parse are indexed with `event.kind: pipeline_error`, the failure in `error.message`, and the raw record in `event.original`.
- Since this integration expires threat indicators using an Elastic latest transform, the threat indicators are present in both the source and the destination indices. While this may appear to be duplicate ingestion, it is an implementation detail necessary for properly expiring threat indicators. Anticipate storage requirements accordingly.
- **Security note:** the WhoisFreaks API requires the API key to be sent as an `apiKey` query parameter. The key is redacted wherever this integration logs its internal `state`, but if Elastic Agent's HTTP client logging is raised to `debug` level (for example while troubleshooting), the outgoing request URL, including the API key may appear in agent logs in cleartext. Avoid enabling debug-level logging for this integration unless necessary, and treat agent debug logs as sensitive while doing so.

## Performance and scaling
For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used
{{ inputDocs }}

### API usage
These APIs are used with this integration:
* [WhoisFreaks gTLD/ccTLD Newly Registered Domains stream API](https://whoisfreaks.com/documentation/newly-registered-domains)
* WhoisFreaks threat feed stream API (`/v3.4/stream/threat-feed/malware`, `/phishing`, and `/spam`)

### Vendor documentation links
- [WhoisFreaks documentation](https://whoisfreaks.com/documentation)
- [WhoisFreaks WHOIS database download](https://whoisfreaks.com/products/whois-database)

### Data streams

#### nrd_with_whois

The `nrd_with_whois` data stream provides Newly Registered Domains with WHOIS records.

##### nrd_with_whois fields
{{ fields "nrd_with_whois" }}

##### nrd_with_whois sample event
{{ event "nrd_with_whois" }}

#### nrd_without_whois

The `nrd_without_whois` data stream provides Newly Registered Domains without WHOIS records.

##### nrd_without_whois fields
{{ fields "nrd_without_whois" }}

##### nrd_without_whois sample event
{{ event "nrd_without_whois" }}

#### threat_feed_malware

The `threat_feed_malware` data stream provides WhoisFreaks malware domain indicators.

##### threat_feed_malware fields
{{ fields "threat_feed_malware" }}

##### threat_feed_malware sample event
{{ event "threat_feed_malware" }}

#### threat_feed_spam

The `threat_feed_spam` data stream provides WhoisFreaks spam domain indicators.

##### threat_feed_spam fields
{{ fields "threat_feed_spam" }}

##### threat_feed_spam sample event
{{ event "threat_feed_spam" }}

#### threat_feed_phishing

The `threat_feed_phishing` data stream provides WhoisFreaks phishing domain indicators.

##### threat_feed_phishing fields
{{ fields "threat_feed_phishing" }}

##### threat_feed_phishing sample event
{{ event "threat_feed_phishing" }}

### Expiration of Indicators of Compromise (IOCs)

The `threat_feed_malware`, `threat_feed_phishing`, and `threat_feed_spam` data streams
expire threat indicators after the duration configured in the **IOC Expiration Duration**
setting (default `90d`), counted from `threat.indicator.last_seen`, or earlier when
**Replace indicators from the previous file** is enabled (see
[Replacing indicators from the previous file](#replacing-indicators-from-the-previous-file)). An
[Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html)
is created for every source index to make sure only active threat indicators are available
to the end users. Each transform creates a destination index named
`logs-ti_whoisfreaks_latest.dest_*` which only contains active and unexpired threat indicators.
Destination indices are aliased to `logs-ti_whoisfreaks_latest.<data_stream_name>`.

| Source data stream                              | Destination index pattern                                 | Destination alias                                     |
|:------------------------------------------------|:----------------------------------------------------------|:------------------------------------------------------|
| `logs-ti_whoisfreaks.threat_feed_malware-*`     | `logs-ti_whoisfreaks_latest.dest_threat_feed_malware-*`   | `logs-ti_whoisfreaks_latest.threat_feed_malware`      |
| `logs-ti_whoisfreaks.threat_feed_phishing-*`    | `logs-ti_whoisfreaks_latest.dest_threat_feed_phishing-*`  | `logs-ti_whoisfreaks_latest.threat_feed_phishing`     |
| `logs-ti_whoisfreaks.threat_feed_spam-*`        | `logs-ti_whoisfreaks_latest.dest_threat_feed_spam-*`      | `logs-ti_whoisfreaks_latest.threat_feed_spam`         |

#### ILM Policy

To facilitate IoC expiration, source data stream-backed indices `.ds-logs-ti_whoisfreaks.<data_stream_name>-*`
are allowed to contain duplicates from each polling interval. ILM policy
`logs-ti_whoisfreaks.<data_stream_name>-default_policy` is added to these source indices, so it
doesn't lead to unbounded growth. This means that in these source indices data is deleted
about `5 days` after it was ingested.

{{ ilm }}

{{ transform }}


## Dashboards

The integration installs two dashboards. Open them from **Analytics → Dashboard**
after install (filter by tag **WhoisFreaks**).

**[Logs WhoisFreaks] Overview** (opens on the last 7 days) covers the newly
registered domain data streams:

- `nrd_with_whois`: total records, unique domains, and unique registrars; records
  over time; top registrars and name servers; domains table
- `nrd_without_whois`: domain count and domains over time

**[Logs WhoisFreaks] Threat Feeds** (opens on the last 90 days) covers the active (latest) indicators from the
`threat_feed_malware`, `threat_feed_phishing`, and `threat_feed_spam` transforms:

- Active indicators, unique domains, and average confidence
- Active indicators by last seen, split by feed
- Indicators by feed, confidence, and threat type
- Most recently seen indicators table

The threat feed indicators set `threat.feed.dashboard_id` to this dashboard, so the
Security **Intelligence** page links each WhoisFreaks feed to it.

> **Note on `whoisfreaks.days_until_expiry`:** this value is computed once at
> ingest time as the difference between the record's `query_time` and its
> `expiry_date`. It is not recomputed as time passes. If you need an up-to-date
> value, compute days-to-expiry from `whoisfreaks.expiry_date` against `now`
> (for example, a runtime field) rather than relying on the stored value.
