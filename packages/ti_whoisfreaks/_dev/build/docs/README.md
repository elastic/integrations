{{- generatedHeader }}
# WhoisFreaks Integration for Elastic

## Overview

The WhoisFreaks integration collects the daily gTLD "domainer" WHOIS database
feed published by [WhoisFreaks](https://whoisfreaks.com/) and indexes it into
Elasticsearch. Each poll downloads a `.csv.gz` file containing one row per
domain (registrar, registrant/admin/tech/billing contacts, name servers,
status codes, and dates), decompresses and parses it, and publishes one
document per domain record.

### Compatibility

This integration requires a WhoisFreaks account with an active **Domainer
Subscription** and an API key from the WhoisFreaks billing dashboard.

### How it works

The `whois` data stream uses the Elastic Agent **CEL input** to:

1. Issue an HTTPS GET request to the WhoisFreaks gTLD domainer download
   endpoint, with `whois=true` and (optionally) `date` sent as **query
   parameters**, and the API key sent as an `X-API-KEY` **request header**.
2. Decompress the gzip response body and parse it as a headered CSV via
   `.mime("application/gzip").mime("text/csv; header=present")`.
3. Map each CSV row to a `whoisfreaks.*` field group and emit it as an
   event.
4. Run the result through an ingest pipeline that sets `@timestamp`,
   parses the WHOIS dates, derives `whoisfreaks.days_until_expiry` and
   `whoisfreaks.is_newly_registered`, and fingerprints
   `domain_name` + `query_time` into the document `_id` for idempotent
   re-polling.

## What data does this integration collect?
The WhoisFreaks integration collects log messages of the following types:
* Domain WHOIS records for gTLDs.

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
2. Set Resource URL to the base gTLD download endpoint (no query string).
3. Paste your API Key.
4. Leave File Date empty to always fetch the latest file, or pin a
   `yyyy-MM-dd` value.
5. Set Resource Interval to `24h`.

### Validation

Open Discover on `logs-ti_whoisfreaks.whois-*` and confirm documents with
populated `whoisfreaks.domain_name` and a parsed `@timestamp` are arriving.

## Troubleshooting

- No data is being collected: confirm the API key and Domainer Subscription are valid; check `error.message` on `pipeline_error` events for the upstream HTTP status.
- Empty or unexpectedly small CSV: the pinned date may not have a published file yet; leave File Date empty.
- Requests time out: increase `resource.timeout` for slow links or very large files.

## Performance and scaling
For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used
{{ inputDocs }}

### API usage
These APIs are used with this integration:
* [WhoisFreaks gTLD/ccTLD Newly Registered Domains download API](https://whoisfreaks.com/documentation/newly-registered-domains)

### Vendor documentation links
- [WhoisFreaks documentation](https://whoisfreaks.com/documentation)
- [WhoisFreaks WHOIS database download](https://whoisfreaks.com/products/whois-database)

### Data streams

#### whois

The `whois` data stream provides WHOIS domain intelligence records.

##### whois fields
{{ fields "whois" }}

##### whois sample event
{{ event "whois" }}

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

## Detection rules

The following **Elastic Security** detection rules are installed with the package (Security → Rules):

| Rule | Severity | Purpose |
|------|----------|---------|
| WhoisFreaks - Newly Registered Domain Observed | Medium | Domains with `is_newly_registered: true` (same-day create/query) |
| WhoisFreaks - Domain Expiring Within 30 Days | Low | Portfolio / takeover risk for domains near expiry |
| WhoisFreaks - Ingest Pipeline or API Error | Low | Collection health (invalid API key, download failures) |

Enable the rules that match your monitoring goals. Rules query `logs-ti_whoisfreaks.whois-*`.
