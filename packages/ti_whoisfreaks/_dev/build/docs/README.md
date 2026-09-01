{{- generatedHeader }}
# WhoisFreaks Integration for Elastic

The WhoisFreaks integration collects the daily gTLD and ccTLD "domainer" WHOIS
database feeds published by [WhoisFreaks](https://whoisfreaks.com/) and indexes
them into Elasticsearch. Each poll pages through the changed feed(s) as
headered CSV (registrar, registrant/admin/tech/billing contacts, name
servers, status codes, and dates), and publishes one document per domain
record (tagged with `whoisfreaks.tld_type`).

### Compatibility

This integration requires a WhoisFreaks account with an active **Domainer
Subscription** and an API key from the WhoisFreaks billing dashboard.

### How it works

The `nrd_with_whois` data stream uses the Elastic Agent **CEL input** to:

1. Query the public WhoisFreaks **status endpoint** (`/v3.3/status`) and read
   `newly.gtld.last_update` and `newly.cctld.last_update`. These hold the
   dates of the latest available gTLD and ccTLD files.
2. Compare each date against the last file of that type already ingested, which
   is tracked in two independent cursors in the input's persistent state. A feed
   whose date is unchanged is skipped, so re-polling never re-ingests the
   same daily file. The two feeds advance independently, so if the gTLD file
   publishes before the ccTLD file, each is pulled as soon as it appears.
3. For each feed with a newer date, page through the corresponding stream
   endpoint (`/gtld` or `/cctld`) with `whois=true`, `date`, `limit`, and a
   growing `offset` as query parameters, and the API key sent as the
   `apiKey` query parameter, parsing each page as a headered CSV via
   `.mime("text/csv; header=present")`. Paging for that feed continues until
   a page comes back with fewer rows than the page size.
4. Map each CSV row to a `whoisfreaks.*` field group, tag it with
   `whoisfreaks.tld_type` (`gtld` or `cctld`), emit it as an event, and advance
   that feed's cursor to the ingested date once paging for that feed
   completes.
5. Run the result through an ingest pipeline that sets `@timestamp`,
   parses the WHOIS dates, derives `whoisfreaks.days_until_expiry` and
   `whoisfreaks.is_newly_registered`, and fingerprints
   `tld_type` + `domain_name` + `query_time` into the document `_id` for
   idempotent re-polling.

A pinned **File Date** overrides steps 1 and 2 and pages that specific date once
for both feeds. Because the status check gates each feed's paging, you can safely
set a short **Resource Interval** (for example `1h`) without repeatedly re-paging
the daily files: only the poll that first sees a new date for a feed triggers
paging for it.


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
2. Set Resource URL to the base domainer stream endpoint (no TLD segment or query string).
3. Paste your API Key.
4. Leave File Date empty to always fetch the latest file, or pin a
   `yyyy-MM-dd` value.
5. Set Resource Interval to `24h`.

### Validation

Open Discover on `logs-ti_whoisfreaks.nrd_with_whois-*` and confirm documents with
populated `whoisfreaks.domain_name` and a parsed `@timestamp` are arriving.

## Troubleshooting

- No data is being collected: confirm the API key and Domainer Subscription are valid; check `error.message` on `pipeline_error` events for the upstream HTTP status.
- Empty or unexpectedly small CSV: the pinned date may not have a published file yet; leave File Date empty.
- An upstream API failure (non-200 response) on any of the five data streams is indexed as a single `event.kind: pipeline_error` document with `error.code`/`error.message` populated and no `event.category`, `event.type`, or `threat.*` fields set, so it is not mistaken for a normal indicator or WHOIS record.
- **Security note:** the WhoisFreaks API requires the API key to be sent as an `apiKey` query parameter. The key is redacted wherever this integration logs its internal `state`, but if Elastic Agent's HTTP client logging is raised to `debug` level (for example while troubleshooting), the outgoing request URL, including the API key may appear in agent logs in cleartext. Avoid enabling debug-level logging for this integration unless necessary, and treat agent debug logs as sensitive while doing so.

## Performance and scaling
For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used
{{ inputDocs }}

### API usage
These APIs are used with this integration:
* [WhoisFreaks gTLD/ccTLD Newly Registered Domains stream API](https://whoisfreaks.com/documentation/newly-registered-domains)

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

{{ ilm }}

{{ transform }}


## Dashboards

The integration installs an **[WhoisFreaks] Overview** dashboard with:

- Total and unique domain counts
- Records over time
- Top registrars and name servers
- Top domains table
- Guidance for newly registered and expiring-domain detection

Open it from **Analytics → Dashboard** after install (filter by tag **WhoisFreaks**).


> **Note on `whoisfreaks.days_until_expiry`:** this value is computed once at
> ingest time as the difference between the record's `query_time` and its
> `expiry_date`. It is not recomputed as time passes. For this daily
> newly-registered feed the value stays accurate, because records are ingested
> the day they are captured, so the "Domain Expiring Within 30 Days" rule sees
> fresh values. If you reuse the data for long-lived domains, compute
> days-to-expiry from `whoisfreaks.expiry_date` against `now` (for example, a
> runtime field) rather than relying on the stored value.
