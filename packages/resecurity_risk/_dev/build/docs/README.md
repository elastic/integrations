# Resecurity RISK Integration for Elastic

## Overview

[Resecurity RISK](https://www.resecurity.com/) is a threat intelligence platform that monitors alerts, indicators of compromise, leaked-credential data breaches, and dark web activity relevant to an organization.

The Resecurity RISK integration for Elastic collects that intelligence from the Resecurity RISK REST API and lets you search, correlate, and visualize it in Kibana alongside the rest of your security data.

### Compatibility

This integration is compatible with the Resecurity RISK REST API as exposed by both the RISK (`https://risk.resecurity.com/api`) and the app (`https://app.resecurity.com/api`) products.

### How it works

The integration periodically polls the Resecurity RISK REST API using the Common Expression Language (CEL) input. Each data stream requests one endpoint, walks the paginated result set, and publishes each record as a document. Documents are keyed by the record's own identifier, so re-collecting a record updates the existing document rather than creating a duplicate.

## What data does this integration collect?

The integration collects the following types of records:

- `Alert`: Threat intelligence alerts, including subject, content, category, confidence and risk scores, TLP status, associated threat actors, geography, and any embedded IOC or TTP detail (endpoint: `GET /alert/index`).
- `IOC`: Indicators of compromise, including malware name, file hashes, detection ratio, and analysis dates (endpoint: `GET /ioc/index`).
- `IOC Lookup`: Watchlist enrichment for a configured list of MD5/SHA-256 hashes (endpoint: `GET /ioc/search-by-hash`).
- `Breach`: Individual leaked-credential records and their breach source metadata (endpoint: `GET /breaches/index`).
- `Dark Web`: Dark web and underground forum posts matching a search term (endpoint: `GET /dark-web/index`).

### Supported use cases

Bringing Resecurity RISK intelligence into Elastic lets analysts investigate external threat data in the same place as their internal telemetry.

**Alert** and **Dark Web** data support monitoring and triage of externally observed threats against your brand, domains, and executives. Alerts carry vendor risk and confidence scoring plus threat actor attribution, and dark web posts add the underlying forum, channel, and marketplace context.

**IOC** and **IOC Lookup** data support detection and enrichment workflows. The `ioc` data stream brings the full indicator feed into Elastic for correlation against host and network telemetry, while `ioc_lookup` answers the reverse question for a specific watchlist of hashes, recording both hits and misses so the absence of a match is itself observable.

**Breach** data supports credential exposure monitoring. Records are keyed to a search term such as a company domain, so teams can track which accounts appear in which breach sources, along with the attack vector, compromised data categories, and severity score reported for each source.

## What do I need to use this integration?

### From Elastic

Elastic Agent must be installed on a host that can reach the Resecurity RISK API. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

### From Resecurity

You need a Resecurity RISK API key. The API authenticates with an `Authorization: Basic` header containing only the base64-encoded API key; there is no password component.

1. Log in to your Resecurity portal.
2. Retrieve the API key issued for your account.
3. Confirm which base URL your product uses: `https://risk.resecurity.com/api` or `https://app.resecurity.com/api`.

The Breach and Dark Web endpoints do not support listing all records. Both require a search phrase, for example a company domain, brand name, or email address to monitor. To monitor several terms, add one instance of the data stream per term.

## How do I deploy this integration?

### Onboard and configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Resecurity RISK**.
3. Select the **Resecurity RISK** integration from the search results.
4. Select **Add Resecurity RISK** to add the integration.
5. Configure the **Resecurity API base URL** and the **API key**.
6. Enable only the data streams you intend to collect, and configure each one:
    - **Resecurity Alert**: optionally set a search query to restrict alerts by subject or content.
    - **Resecurity IOC**: no additional configuration is required.
    - **Resecurity IOC Lookup**: disabled by default. Enable it and provide the list of MD5/SHA-256 hashes to monitor.
    - **Resecurity Breach**: set the required search query.
    - **Resecurity Dark Web**: set the required search query.
7. Adjust the **Collection Interval** and **Max Pages per Poll** for each data stream if required.
8. Select **Save and continue** to save the integration.

### Validation

1. In the top search bar in Kibana, search for **Discover**.
2. Select the `logs-*` data view.
3. Filter on `data_stream.dataset` for the data streams you enabled, for example `resecurity_risk.alert`, and verify that documents are arriving.

## Troubleshooting

If a request to the Resecurity RISK API fails, the failure is recorded in `error.message` on a document in the corresponding data stream, and the ingest pipeline stops processing that document. Search for `error.message: *` in the data stream to find collection failures, and check the API key and base URL configured for the integration.

The Breach and Dark Web data streams return nothing without a search query; confirm one is configured for each instance.

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Performance and scaling

None of the Resecurity RISK list endpoints used by this integration expose a "since timestamp" filter, so every poll re-walks pages from the start rather than fetching only new records. To bound the work done per poll, each list data stream has a **Max Pages per Poll** setting, which defaults to 10.

Document IDs are derived from the source record's own identifier, so re-ingesting the same record on a later poll overwrites the existing document rather than creating a duplicate. If your feed produces more genuinely new records per interval than `max_pages_per_poll * 100` (the API's default page size), increase **Max Pages per Poll** or shorten the **Collection Interval** to keep up.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Alert

The `alert` data stream provides threat intelligence alerts from Resecurity RISK.

#### alert fields

{{ fields "alert" }}

{{ event "alert" }}

### IOC

The `ioc` data stream provides indicators of compromise from Resecurity RISK.

#### ioc fields

{{ fields "ioc" }}

{{ event "ioc" }}

### IOC Lookup

The `ioc_lookup` data stream provides the result of looking up each configured hash against Resecurity RISK. A match ingests the full IOC record with `resecurity_risk.ioc.found: true`; a miss ingests a compact record with `resecurity_risk.ioc.found: false`.

#### ioc_lookup fields

{{ fields "ioc_lookup" }}

{{ event "ioc_lookup" }}

### Breach

The `breach` data stream provides leaked-credential records and their breach source metadata from Resecurity RISK.

#### breach fields

{{ fields "breach" }}

{{ event "breach" }}

### Dark Web

The `dark_web` data stream provides dark web and underground forum posts from Resecurity RISK.

#### dark_web fields

{{ fields "dark_web" }}

{{ event "dark_web" }}

### Inputs used

{{ inputDocs }}

### API usage

These APIs are used with this integration:

* Alert (endpoint: `GET /alert/index`)
* IOC (endpoint: `GET /ioc/index`)
* IOC Lookup (endpoint: `GET /ioc/search-by-hash`)
* Breach (endpoint: `GET /breaches/index`)
* Dark Web (endpoint: `GET /dark-web/index`)
