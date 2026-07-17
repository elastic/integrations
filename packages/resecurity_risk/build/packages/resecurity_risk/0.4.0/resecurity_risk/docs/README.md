# Resecurity RISK

The Resecurity RISK integration collects Threat Intelligence from the
[Resecurity RISK](https://www.resecurity.com/) REST API. It ships 5 Data Streams:

| Data stream | Source Endpoint | Search Term |
|---|---|---|
| Alert | `GET /alert/index` | optional |
| IOC | `GET /ioc/index` | not supported |
| IOC Lookup | `GET /ioc/search-by-hash` | hash list (**required**) |
| Breach | `GET /breaches/index` | **required** |
| Dark Web | `GET /dark-web/index` | **required** |

## Requirements

You need a Resecurity RISK API key. Resecurity's API Authenticates with an `Authorization: Basic`
Header containing only the **base64-encoded API key**.
Enter your key in the "API key" field of the Integration Policy; make sure you have the corrected URL selected based on your purchased product (in can either be "risk" or "app").

## Breach and Dark Web require a Search Term

Unlike Alert and IOC, the Breach and Dark Web Endpoints do NOT support listing all records. The
upstream API requires a search Phrase (for example a Company Domain, Brand Name, or Email
Address to monitor). Configure this in the "Search Query" field when adding the Breach or Dark
Web Data Stream. To monitor multiple terms, add multiple instances of the Data Stream, one per
term.

## Known Limitation: no incremental collection

None of the 4 Resecurity RISK list endpoints used by this integration expose a "since timestamp"
filter. Every poll re-walks pages from the start rather than fetching only New Records. To bound
the work done per poll, each list data stream has a `max_pages_per_poll` setting (default 10). Document
IDs are derived from the source record's own `id` field, so re-ingesting the same record on a
later poll Overwrites the existing document rather than creating a Duplicate — but if your feed
has more genuinely New Records per interval than `max_pages_per_poll * 100` (the API's default
page size), increase `max_pages_per_poll` or shorten `interval` to keep up.

## Data Streams

### Alert

Threat Intelligence Alerts — subject, content, category, confidence/risk scores, TLP status,
associated threat actors, geography, and any embedded IOC or TTP detail.

### IOC

Indicators of Compromise — malware name, file hashes (MD5/SHA-256), detection ratio, and dates.

### IOC Lookup

Watchlist enrichment: give the stream a list of MD5/SHA-256 hashes and each poll looks every
hash up via `GET /ioc/search-by-hash`. A match ingests the full IOC record with
`resecurity.ioc.found: true`; a miss ingests a compact record with `resecurity.ioc.found: false`.
Documents are keyed by the queried hash, so repeated polls update the same document instead of
creating duplicates. The stream is disabled by default — enable it and provide hashes when you
have a watchlist to monitor.

### Breach

Individual Leaked-Credential Records (email, username, password/password hash) plus the breach
source's metadata (name, category, attack vector, compromised data types, geography).

### Dark Web

Dark Web / underground-forum Posts matching your search term — actor, category, country,
language, title, snippet, and source URL.
