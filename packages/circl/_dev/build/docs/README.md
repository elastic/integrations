{{- generatedHeader }}

# CIRCL Vulnerability-Lookup Integration for Elastic

## Overview

[Vulnerability-Lookup](https://www.vulnerability-lookup.org/) is an open-source platform developed and operated by [CIRCL](https://www.circl.lu/), the Computer Incident Response Center Luxembourg. It aggregates and correlates vulnerability information from many sources independently of the vulnerability identifier scheme, and it manages Coordinated Vulnerability Disclosure workflows.

The CIRCL Vulnerability-Lookup integration for Elastic collects **Known Exploited Vulnerability (KEV) assertions** from a Vulnerability-Lookup instance. A KEV assertion is a statement, published by a named catalog, that a given vulnerability has been observed being exploited somewhere in the world. Unlike a single-source KEV feed, one Vulnerability-Lookup instance aggregates several KEV catalogs at once and normalizes them into a single standardized model.

This integration works against the free public instance at `https://vulnerability.circl.lu` as well as any self-hosted deployment.

### Compatibility

This integration is compatible with Vulnerability-Lookup **v3.0.0 and later**, which is when the `/api/kev/` endpoint first shipped. **v4.0.0 or later is strongly recommended**: earlier releases lacked the unique tiebreaker in the pagination sort order, and because bulk imports share a single assertion timestamp, paginating over that data could silently produce duplicate and skipped records.

The public CIRCL instance runs v5.5.0. You can check the version of any instance by reading `info.version` from `{url}/api/swagger.json`.

### How it works

The integration polls `GET {url}/api/kev/` on a schedule using the Common Expression Language (CEL) input, walking the paginated result set until the catalog is exhausted.

On the **first run** the integration performs a complete catalog backfill, collecting every assertion the instance holds. On **subsequent runs** it requests only records created on or after the date of the previous poll, which keeps steady-state collection to a small number of requests.

Because the API filters at whole-day granularity, each poll necessarily re-returns records already collected earlier the same day. This is expected and harmless: each document is keyed on a fingerprint of the assertion identifier and its status timestamp, so an unchanged record collected twice is silently discarded, while a record whose exploitation status has changed is stored as a new document that preserves the earlier state as history.

## What data does this integration collect?

The CIRCL Vulnerability-Lookup integration collects one type of document:

* **KEV assertions** (`kev` data stream) — Known Exploited Vulnerability assertions in the [GCVE-BCP-07](https://gcve.eu/bcp/gcve-bcp-07/) standardized format, gathered from every KEV catalog present on the instance.

Each assertion carries the vulnerability identifier, exploitation status and the reason for it, provenance identifying which catalog asserted it, supporting evidence with a confidence score, timestamps describing when exploitation was first and last observed, and references.

Which catalogs are present depends on the instance you point at, because catalog composition is an operator choice rather than a product default. The public CIRCL instance currently aggregates five: CISA KEV, KEVIntel, Shadowserver honeypot telemetry, the ENISA CSIRTs Network catalog, and CIRCL's own analyst-authored assertions.

Note that the same vulnerability legitimately appears more than once when several catalogs assert it independently. These are distinct assertions with distinct evidence, not duplicates.

Provenance differs by catalog and is worth understanding before you decide how much weight to give an assertion. The CISA KEV and CIRCL analyst catalogs publish their sourcing and are released under CC0-1.0. Shadowserver and KEVIntel together contribute roughly 70% of the assertions on the public instance, and neither publishes its collection methodology or a data licence. Use `event.provider` and `circl.kev.evidence.confidence` to weight assertions by the strength of their provenance.

### Supported use cases

Ingesting KEV assertions into Elasticsearch lets you prioritize remediation by real-world exploitation rather than by severity score alone.

Correlate the collected assertions against your own vulnerability-scanner findings and asset inventory to identify which of your exposed systems carry a vulnerability that someone is actively exploiting. Because each assertion records which catalog made it and with what confidence, you can weight your response by the strength and provenance of the evidence, and you can track how far ahead of the CISA catalog other sources are. The honeypot telemetry contributed by Shadowserver additionally provides near-real-time exploitation-attempt counts, giving a signal of how much active scanning a given vulnerability is currently attracting.

## What do I need to use this integration?

Elastic Agent must be installed, with network access to reach the Vulnerability-Lookup instance over outbound HTTPS (port 443). No inbound ports, listeners, or webhooks are required.

**No credentials are required.** The KEV endpoints are anonymously readable, so pointing the integration at an instance URL is sufficient.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

### Set up steps in CIRCL Vulnerability-Lookup

No setup is required in Vulnerability-Lookup. The KEV endpoints are readable without authentication.

Optionally, you may supply an API key. A key does not grant access to any additional KEV data — it only moves the client from the anonymous rate-limit tier of 20 requests per minute to the per-key tier of 40 requests per minute. Since a complete catalog backfill takes only a handful of requests, most deployments do not need one. To obtain a key on the public instance:

1. Register an account at `{url}/user/signup`.
2. Confirm your email address. An unconfirmed account returns HTTP 403 `Account is not confirmed` even though a key has already been generated for it.
3. Read the key from `{url}/user/profile`.

Keys do not expire and are rotated rather than renewed. No role or permission is needed to read KEV data.

#### Vendor resources

- [Vulnerability-Lookup documentation](https://www.vulnerability-lookup.org/documentation/)
- [API access patterns](https://www.vulnerability-lookup.org/documentation/access-patterns.html)
- [Public instance API browser](https://vulnerability.circl.lu/api/)

### Set up steps in Kibana

1. In Kibana, navigate to **Management** > **Integrations**.
2. Search for **CIRCL Vulnerability-Lookup** and select it.
3. Select **Add CIRCL Vulnerability-Lookup**.
4. Configure the integration:
   - **URL** (required): the base URL of the Vulnerability-Lookup instance, including the scheme. Defaults to the public CIRCL instance at `https://vulnerability.circl.lu`. Do not include the `/api` path.
   - **Interval** (required): how often the catalog is polled. Defaults to `1h`. Responses from the public instance are cached for 30 minutes, so polling faster than that cannot return fresher data.
   - **API Key** (optional): leave empty unless you specifically want the higher rate-limit tier.
   - **Initial Interval** (optional): how far back to collect on the first run. **Leave this empty**, which performs a complete catalog backfill and is the recommended setting. See the note below before setting a value.
   - **Tags**: applied to every collected document. Defaults to `forwarded` and `circl-kev`.
5. Select **Save and continue**.

A note on **Initial Interval**, because it does not behave the way the name suggests. The date filter applies to an internal timestamp recording when a record was imported into the Vulnerability-Lookup instance, not when the vulnerability was added to a KEV catalog. On the public instance, that import timestamp is floored at the date the catalog was first bulk-loaded, so a 30-day initial window returns roughly 2% of the catalog with nothing to indicate the shortfall. KEV data is a reference catalog whose value lies in being complete, so a full backfill is almost always what you want. Only set this value if you deliberately need to bound the size of the first collection.

### Validation

1. Navigate to **Management** > **Integrations** > **Installed integrations** and confirm the integration reports as healthy.
2. In **Discover**, query the `logs-circl.kev-*` data view. Documents should appear within one polling interval of installation.
3. Confirm that `vulnerability.id` and `event.provider` are populated. The value of `event.provider` identifies which catalog asserted the exploitation.

## Troubleshooting

- No data is being collected: Confirm the agent host can reach the instance over HTTPS on port 443, and that the configured URL is the base URL of the instance without the `/api` suffix. Verify the endpoint is reachable with `curl "{url}/api/kev/?per_page=1"`, which should return JSON without requiring any credential.

- Collection stalls and then reports an error after about 30 seconds: The public instance sits behind a cache whose backend-fetch timeout is 30 seconds, and a small fraction of cache-miss requests return a transient HTTP 503 after stalling for that long. These recover on the next attempt. This is why the HTTP client timeout defaults to `120s` — do not lower it below 30 seconds.

- HTTP 403 `Account is not confirmed`: You supplied an API key belonging to an account whose email address has not been confirmed. Either confirm the address or clear the API Key setting, since no key is needed to read KEV data.

- Far fewer documents than expected on the first run: The **Initial Interval** setting is populated. Clear it to perform a complete backfill. See the note in the Kibana setup steps above.

- A vulnerability appears several times: This is expected. Each document is a separate assertion from a different catalog, distinguished by `event.provider` and `circl.kev.gcve.origin_uuid`.

- Changes in exploitation status are not appearing: The API offers no filter on record modification time and no deletion or tombstone feed, so steady-state windowed polling only observes newly created assertions. A status change on an assertion collected previously, or the removal of an assertion upstream, is not detectable incrementally. This is a limitation of the source API rather than of the integration.

## Performance and scaling

This integration collects a small, bounded reference catalog rather than a continuous event stream. At the time of writing, the public CIRCL instance holds roughly 5,700 assertions totalling about 9.5 MB, which a first-run backfill retrieves in six requests. Steady-state polling at the default hourly interval retrieves only records created since the previous poll, so ongoing cost is negligible.

The vendor's access-patterns documentation asks consumers not to repeatedly enumerate the API to mirror the dataset. The integration is built accordingly: it performs one complete pull to bootstrap itself and then switches to windowed collection. Please do not work around this by reinstalling the integration to force repeated full pulls.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

The reference below describes the CEL input in general terms, including credential and endpoint options that other integrations rely on. This integration requires no credentials and builds its own request URL, so only the settings listed in the Kibana setup steps above apply here.

{{ inputDocs }}

### API usage

This integration uses the following API:

* `GET {url}/api/kev/` — lists GCVE-BCP-07 KEV assertions across every catalog on the instance, with offset pagination and an optional day-granular date filter. This is the same endpoint and pagination pattern that Vulnerability-Lookup's own instance-to-instance synchronization service uses.

### Vendor documentation links

- [Vulnerability-Lookup documentation](https://www.vulnerability-lookup.org/documentation/)
- [API access patterns](https://www.vulnerability-lookup.org/documentation/access-patterns.html)
- [GCVE-BCP-07 KEV assertion specification](https://gcve.eu/bcp/gcve-bcp-07/)
- [Vulnerability-Lookup source repository](https://github.com/vulnerability-lookup/vulnerability-lookup)

### Data streams

#### KEV

The `kev` data stream provides Known Exploited Vulnerability assertions from `GET {url}/api/kev/`, in the GCVE-BCP-07 format, covering every KEV catalog present on the instance.

Fields that are common to all assertions are mapped to ECS. Evidence supplied by the asserting catalog varies in shape from one catalog to the next, so the highest-value keys are promoted to named fields under `circl.kev.*` and the remainder are retained in the flattened `circl.kev.evidence.details` object.

##### kev fields

{{ fields "kev" }}

##### kev sample event

{{ event "kev" }}

{{ ilm }}

{{ transform }}
