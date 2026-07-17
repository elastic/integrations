# Resecurity RISK

The Resecurity RISK integration collects Threat Intelligence from the
[Resecurity RISK](https://www.resecurity.com/) REST API. It ships 4 Data Streams:

| Data stream | Source Endpoint | Search Term |
|---|---|---|
| Alert | `GET /alert/index` | optional |
| IOC | `GET /ioc/index` | not supported |
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

None of the 4 Resecurity RISK endpoints used by this integration expose a "since timestamp"
filter. Every poll re-walks pages from the start rather than fetching only New Records. To bound
the work done per poll, each data stream has a `max_pages_per_poll` setting (default 10). Document
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

### Breach

Individual Leaked-Credential Records (email, username, password/password hash) plus the breach
source's metadata (name, category, attack vector, compromised data types, geography).

### Dark Web

Dark Web / underground-forum Posts matching your search term — actor, category, country,
language, title, snippet, and source URL.
