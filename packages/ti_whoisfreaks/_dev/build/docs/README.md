{{- generatedHeader }}
# WhoisFreaks Integration for Elastic

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

This integration requires a WhoisFreaks account with an active **Domainer
Subscription** and an API key from the WhoisFreaks billing dashboard.

### How it works

The integration contains five Elastic Agent CEL inputs. The two newly registered
domain inputs track the last ingested file date per feed in the input cursor; the
three threat feed inputs keep no persistent state and page the whole daily snapshot
on every poll. All of them emit one document per row or domain.

#### `nrd_with_whois`

The `nrd_with_whois` data stream uses the Elastic Agent **CEL input** to:

1. Query the public WhoisFreaks **status endpoint** (`/v3.3/status`) and read
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
   **File Date**) return the input to the status check.
5. Run the result through an ingest pipeline that preserves the raw record in
   `event.original`, parses it into `whoisfreaks.*`, sets `@timestamp`, parses the
   WHOIS dates, derives `whoisfreaks.days_until_expiry` and
   `whoisfreaks.is_newly_registered`, and fingerprints `tld_type` +
   `domain_name` + `query_time` into the document `_id` for idempotent
   re-polling.

A pinned **File Date** overrides steps 1 and 2 and pages that specific date once
for both feeds. Because the status check gates each feed's paging, you can safely
use a daily **Interval** such as `24h` without repeatedly re-paging the
daily files: only the poll that first sees a new date for a feed triggers paging
for it, and it pages that file in the same poll.

The status endpoint only reports the latest file date, so a file that is published
and superseded while the agent is not polling (for example during an outage) is not
collected automatically. To backfill a missed day, set **File Date** to that day,
wait for it to be ingested, and then clear the setting again.

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

In production, this stream is typically polled once per day (`24h`) unless you
explicitly need more frequent checks for a controlled test or short-term
investigation.

#### Threat feeds: `threat_feed_malware`, `threat_feed_phishing`, `threat_feed_spam`

The three threat feeds are daily snapshot endpoints under the WhoisFreaks
v3.4 threat-feed API. There is no status endpoint that exposes a per-feed
"latest file" marker, so each poll pages through the whole snapshot. The
practical production pattern is therefore a daily poll (`24h`):

1. Request the feed endpoint for the relevant category (`malware`, `phishing`,
   or `spam`), paging with `limit` and a growing `offset` until a page comes back
   short.
2. Emit each CSV row as the raw `message`, which the ingest pipeline preserves
   in `event.original` and parses.
3. Emit one event per row with ECS threat fields (for example, `threat.indicator.type`
   and the feed-specific metadata).
4. Index upstream non-200 responses as error documents with `error.code` and
   `error.message` set rather than as threat indicators.

Each row is fingerprinted on `threat.indicator.url.domain` + `threat.indicator.last_seen`
into the document `_id`. Because the source data streams roll over daily (see
[ILM Policy](#ilm-policy)), each daily poll re-indexes the snapshot into the source
data stream; the latest transform keeps one document per domain. Indicators are
expired as described in
[Expiration of Indicators of Compromise (IOCs)](#expiration-of-indicators-of-compromise-iocs).
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
* A WhoisFreaks account with a Domainer Subscription and an API key.
* This integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview)
  for the threat feeds. For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup)
  setup and requirements.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

### Set up steps in WhoisFreaks

1. Sign in to the WhoisFreaks billing dashboard and confirm an active
   Domainer Subscription.
2. Copy your API key from the dashboard.

#### Vendor resources
- [WhoisFreaks Newly Registered Domains API docs](https://whoisfreaks.com/documentation/newly-registered-domains)
- [WhoisFreaks documentation home](https://whoisfreaks.com/documentation)

### Set up steps in Kibana

1. Add the WhoisFreaks integration to an Agent policy.
2. Paste your API key in the integration-level **API Key** setting.
3. For each data stream, confirm the base **URL** (for the threat feeds this setting
   is under **Advanced options**):
   - `nrd_with_whois` and `nrd_without_whois`: use the base domainer stream endpoint
     (for example `https://files.whoisfreaks.com/v3.3/stream/domainer`), without
     the `gtld`/`cctld` suffix or query string.
   - `threat_feed_malware`, `threat_feed_phishing`, `threat_feed_spam`: use the
     corresponding threat-feed base URL provided by WhoisFreaks for that feed.
4. For the WHOIS streams, leave **File Date** empty to always fetch the latest
   published file, or pin a specific `yyyy-MM-dd` value when you need a fixed
   historical file. For the threat feeds, use the default daily cadence and keep
   **Interval** at `24h` unless you deliberately need a different polling
   period. Adjust **IOC Expiration Duration** (default `90d`) to control how long
   threat indicators stay active after they were last seen.
5. Use the default daily interval (`24h`) for the three threat feeds and the
   domain-only stream; the WHOIS stream can also be safely scheduled daily or
   more frequently if you need faster detection for a new file.
6. Save the integration and confirm the Agent starts collecting data.

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

- No data is being collected: confirm the API key and Domainer Subscription are valid; check `error.code` and `error.message` on error documents for the upstream HTTP status.
- Empty or unexpectedly small CSV: the pinned date may not have a published file yet; leave File Date empty.
- An upstream API failure (non-200 response) on any of the five data streams is indexed as a single document with `error.code`, `error.id`, and `error.message` populated and no `event.category`, `event.type`, or `threat.*` fields set, so it is not mistaken for a normal indicator or WHOIS record. Search for them with the KQL query `data_stream.dataset: ti_whoisfreaks.* AND error.message: *`.
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
setting (default `90d`), counted from `threat.indicator.last_seen`. An
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

The integration installs a **[Logs WhoisFreaks] Overview** dashboard with:

- Total records, unique domains, and unique registrars
- Records over time
- Top registrars and name servers
- Domains table

Open it from **Analytics → Dashboard** after install (filter by tag **WhoisFreaks**).
The dashboard covers the `nrd_with_whois` data stream.

> **Note on `whoisfreaks.days_until_expiry`:** this value is computed once at
> ingest time as the difference between the record's `query_time` and its
> `expiry_date`. It is not recomputed as time passes. If you need an up-to-date
> value, compute days-to-expiry from `whoisfreaks.expiry_date` against `now`
> (for example, a runtime field) rather than relying on the stored value.
