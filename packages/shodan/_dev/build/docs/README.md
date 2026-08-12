# Shodan Integration for Elastic

## Overview

The Shodan integration collects internet-exposure threat intelligence from [Shodan](https://www.shodan.io/) and its free Certificate Transparency Logs (CTL) service. It has two independent parts:

* **Host Search**: polls Shodan for a query you define and maps each matching host — open ports, software, known vulnerabilities, geolocation — into ECS `threat.indicator` fields. Requires a Shodan account and API key.
* **Certificate Transparency**: polls Shodan's free CTL service for a domain you configure and maps each observed certificate — subject/issuer, validity window, alternative names — into ECS `threat.indicator.x509` fields. No account needed.

### How it works

**Host Search** polls on an interval and pages through results up to **Max Pages Per Collection Interval** (default `10` pages, 100 results each; leave empty for no cap). Shodan bills API credits per page, so this cap protects against a broad query burning through your credit balance in a single interval — see [Performance and scaling](#performance-and-scaling) below. Re-polling the same host (same IP+port) updates its existing record instead of creating a duplicate.

**Certificate Transparency** polls once per interval and returns every certificate for the domain in a single request — no pagination, no credit cost. Re-observing the same certificate (same hash) doesn't create a duplicate.

## What data does this integration collect?

* **Host threat indicators**: internet-exposed hosts matching your Shodan query — IP, port, software/version, CVEs, geolocation, ASN/ISP.
* **Certificate transparency records**: certificates observed for your configured domain — subject/issuer, validity window, alternative (SAN) names.

### Supported use cases

**Host Search**: inventory your (or a third party's) internet-facing attack surface, enrich security events by correlating IPs against Shodan-reported exposure, or alert on newly-exposed vulnerabilities.

**Certificate Transparency**: discover subdomains you didn't know existed, or alert when a certificate for your domain is issued by an unrecognized CA — a common sign of mis-issuance or domain compromise.

## What do I need to use this integration?

* An Elastic Agent installation, either self-managed or through Elastic Cloud.
* Host Search only: a [Shodan account](https://account.shodan.io/register) with an API key. Some search filters (e.g. `has_vuln`) require a paid membership — see [Shodan's pricing](https://www.shodan.io/pricing).
* Certificate Transparency needs no account or API key.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed — see the [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). Elastic Agent polls the Shodan API directly, so no additional infrastructure is required on your network.

### Set up steps in Shodan

For Host Search:

1. Sign in (or register) at [account.shodan.io](https://account.shodan.io/).
2. Copy your API key from your [account page](https://account.shodan.io/).
3. Decide on a Shodan [search query](https://www.shodan.io/search/filters) for the hosts you want to monitor (e.g. `has_vuln:true`, `org:"My Company" country:US`, `port:3389`).

Certificate Transparency needs no setup in Shodan — just pick the domain you want to monitor.

#### Vendor resources

- [Shodan API documentation](https://developer.shodan.io/api)
- [Shodan search query filters](https://www.shodan.io/search/filters)
- [Shodan account/API key page](https://account.shodan.io/)
- [Shodan CTL service](https://ctl.shodan.io/)

### Set up steps in Kibana

1. In Kibana, go to **Management > Integrations**.
2. Search for **Shodan** and click **Add Shodan**.
3. Configure whichever of the two policy templates you need:
    - **Shodan Host Search**:
        - **Shodan API Key**
        - **Search Query** (defaults to `has_vuln:true`)
        - **Collection Interval** (defaults to `24h`)
        - **Max Pages Per Collection Interval** (defaults to `10`; leave empty for no cap)
        - **Preserve Original Event** — optionally keep the raw Shodan JSON for debugging
    - **Shodan Certificate Transparency**:
        - **Domain** (e.g. `example.com`)
        - **Collection Interval** (defaults to `24h`)
        - **Preserve Original Event** — optionally keep the raw CTL JSON for debugging
4. Save the integration.

### Validation

**Host Search**: after one collection interval, check **Discover** with the `logs-shodan.host-*` data view — you should see one document per matching host. No documents? Confirm the API key is valid and the query returns results at [shodan.io/search](https://www.shodan.io/search).

**Certificate Transparency**: check `logs-shodan.domain-*` in Discover — one document per certificate. No documents? Confirm the domain has publicly-issued certificates via [crt.sh](https://crt.sh/).

## Troubleshooting

**Host Search:**
- No data: verify the API key is valid and hasn't hit its credit limit.
- Fewer results than expected: some filters (`has_vuln`, `vuln`) need a paid tier; also check whether **Max Pages Per Collection Interval** is capping results (expected, not an error).
- High credit usage: narrow your query (e.g. scope to a `hostname`, `org`, or `net` range) and keep **Max Pages Per Collection Interval** set, not empty.

**Certificate Transparency:**
- No data: confirm the domain is spelled correctly and has publicly-issued certificates.

## Performance and scaling

Shodan bills credits per page for Host Search (100 results/page) and enforces per-plan rate limits. Keep the collection interval conservative (default `24h`) and **Max Pages Per Collection Interval** deliberate — a broad query can match millions of hosts, and without a cap one interval could exhaust your credit balance.

Certificate Transparency has no pagination or credit cost — it scales independently of Host Search.

For more on scaling architectures, see [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures).

## Reference

### Inputs used

{{ inputDocs }}

### API usage

* [Shodan Host Search API](https://developer.shodan.io/api#host-search) (`/shodan/host/search`)
* [Shodan CTL service](https://ctl.shodan.io/) (`/api/v1/domain/{domain}`)

### Vendor documentation links

- [Shodan API documentation](https://developer.shodan.io/api)
- [Shodan search query filters](https://www.shodan.io/search/filters)
- [Shodan account/API key page](https://account.shodan.io/)
- [Shodan CTL service](https://ctl.shodan.io/)

### Data streams

#### host

The `host` data stream provides internet-exposed host records from Shodan host search results.

##### host fields

{{ fields "host" }}

##### host sample event

{{ event "host" }}

#### domain

The `domain` data stream provides certificate transparency records for a configured domain, collected via Shodan's free CTL service.

##### domain fields

{{ fields "domain" }}

##### domain sample event

{{ event "domain" }}

### Latest host indicator state

The raw `host` data stream is append-only, so re-detecting the same `ip:port` doesn't update the existing document. For a current, deduplicated view, this integration installs a transform that rolls the raw stream up into a "latest state" index keyed by IP and port, dropping indicators not re-confirmed within 7 days. Query it at `logs-shodan_latest.host`.

`domain` has no equivalent transform — certificates are already deduplicated by hash, so there's no "latest state" to roll up to.
{{ transform }}
