{{ generatedHeader }}


# TYCHON Quantum Command Integration for Elastic

## Overview

[TYCHON Quantum Command](https://tychon.io/products/tychon/pqc-management-module/) helps organizations inventory cryptographic implementations, assess post-quantum exposure, and prioritize remediation across endpoints, applications, certificates, network services, key stores, and platform readiness. This integration ingests TYCHON Quantum Command output files into Elastic, normalizes the source stream, and publishes entity-focused transform destinations for dashboards, search, and reporting.

### Compatibility

* Intended for environments where TYCHON Quantum Command produces NDJSON or JSON output files on Windows, Linux, or macOS systems.
* Requires a valid TYCHON Quantum Command license.
* Requires Elastic Stack / Fleet compatible with package version `0.1.0` and the package manifest constraint `>=8.11.0 <10.0.0`.

### How it works

1. TYCHON Quantum Command writes scan results to local `.ndjson` or `.json` files.
2. Elastic Agent collects those files through the `filestream` input in the `tychon_pqc` data stream.
3. The ingest pipeline stores the raw events in the namespace-specific source data stream `logs-tychon_quantum_command.tychon_pqc-<namespace>`.
4. Elasticsearch transforms filter the combined source stream by `tychon.index` and publish current-state upsert/entity destination indices such as `tychon-pqc-inventory`, `tychon-pqc-certificates`, and `tychon-pqc-system-readiness`.
5. Kibana dashboards and saved objects query both the raw and transformed views for operational analysis.

## What data does this integration collect?

The integration collects file-based TYCHON Quantum Command output in NDJSON or JSON form. The package is designed around one primary ingest stream and multiple analytical transforms.

### Primary ingest stream

* Data stream: `tychon_pqc`
* Data stream type: `logs`
* Expected source formats: NDJSON and JSON records written by TYCHON Quantum Command
* Collection method: Elastic Agent `filestream`
* Namespace-safe source data stream pattern used by transforms: `logs-tychon_quantum_command.tychon_pqc-*`
* Index template used by the source data stream: `logs-tychon_quantum_command.tychon_pqc`
* Backing index naming pattern for the source data stream: `.ds-logs-tychon_quantum_command.tychon_pqc-<namespace>-YYYY.MM.DD-000001`

### Analytical datasets produced by transforms

The package currently publishes the following current-state upsert/entity destination indices from the shared source stream. These indices are not raw event data streams; each transform uses `observer.id` and `tychon.record.id` as the latest transform identity so rescans update the same entity record.

* `tychon-pqc-applications`
* `tychon-pqc-archives`
* `tychon-pqc-assets`
* `tychon-pqc-certificates`
* `tychon-pqc-ciphers`
* `tychon-pqc-crypto-libraries`
* `tychon-pqc-installed-apps`
* `tychon-pqc-installed-browser-extensions`
* `tychon-pqc-inventory`
* `tychon-pqc-ipsec-tunnels`
* `tychon-pqc-keystores`
* `tychon-pqc-macsec`
* `tychon-pqc-system-readiness`
* `tychon-pqc-vpn-clients`

### Supported use cases

* Build a cryptographic inventory across endpoints and applications.
* Identify classical algorithms, deprecated protocols, and post-quantum readiness gaps.
* Review certificate and keystore exposure, including signature and key algorithm posture.
* Track TLS, VPN, IPsec, MACsec, and related network cryptography risk.
* Estimate remediation readiness and cost through the `system-readiness` transform.
* Drive dashboards for inventory, application reporting, certificate operations, and cost analysis.

## What do I need to use this integration?

* Elastic Agent enrolled in Fleet.
* Access to the host or file share where TYCHON Quantum Command writes scan output.
* File system permissions that allow Elastic Agent to read the output directory.
* A deployment decision for the Fleet namespace. The package supports any namespace; transforms read from `logs-tychon_quantum_command.tychon_pqc-*`.
* Enough Elasticsearch capacity for the raw source stream plus the transform destination indices.

## How do I deploy this integration?

### Agent-based deployment

Install Elastic Agent on a host that can read the TYCHON Quantum Command output files. For Elastic Agent installation guidance, see the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Set up steps in TYCHON Quantum Command

1. Configure TYCHON Quantum Command to export scan results in NDJSON format. JSON-formatted records can also be ingested when they are emitted one record per event.
2. Choose a stable output location that Elastic Agent can read.
3. Ensure scan results are written with file permissions that allow the Elastic Agent service account to read them.
4. If you separate environments by namespace in Fleet, keep the TYCHON output pathing and the Elastic policy aligned with the intended namespace.
5. Preserve enough scan history on disk for Elastic Agent to pick up new files reliably.

#### Vendor resources

* [TYCHON Quantum Command product page](https://tychon.io/products/tychon/pqc-management-module/)
* [TYCHON Quantum Command portal](https://acdiscanner.tychon.io/)
* [TYCHON support portal](https://support.tychon.io/)
* [TYCHON contact page](https://tychon.io/products/tychon/pqc-management-module/#ContactUs)

### Set up steps in Kibana

1. Open **Integrations** and install **TYCHON Quantum Command**.
2. Add the integration to an Elastic Agent policy.
3. Set the Windows paths, Linux paths, and any additional custom paths that contain TYCHON output files.
4. Choose the target namespace for the integration policy.
5. Save and deploy the policy.
6. Confirm that documents are arriving in `logs-tychon_quantum_command.tychon_pqc-<namespace>`.
7. Wait for the managed transforms to populate the destination indices.
8. Open the packaged dashboards to validate the transformed views.

### Validation

Use the following checks after deployment:

* Confirm raw ingest by querying `logs-tychon_quantum_command.tychon_pqc-<namespace>` for recent events.
* Confirm dataset routing by checking the `tychon.index` values present in the source stream.
* Confirm transform output by verifying documents appear in indices such as `tychon-pqc-inventory`, `tychon-pqc-certificates`, and `tychon-pqc-system-readiness`.
* Open the packaged dashboards and verify charts populate without missing data view errors.
* Review a few representative documents to confirm timestamps, observer metadata, and TYCHON-specific fields were parsed as expected.
* Confirm `event.ingested` is present on source events. Fleet's final pipeline usually sets this field after the package ingest pipeline, but the package also sets it from `_ingest.timestamp` so pipeline tests and transform sync always have a stable ingest-time field.


## Troubleshooting

* No data in the source stream: verify the file path settings, file permissions, and that TYCHON is actually writing new files.
* Data in the source stream but empty dashboards: verify transforms are running and that the relevant `tychon.index` values exist in the raw events.
* Expected namespace has no transformed data: verify documents are landing in the intended namespace and that transforms can read the shared source pattern `logs-tychon_quantum_command.tychon_pqc-*`.
* Parsing issues: inspect `error.message`, malformed JSON records, and any unexpected multiline output in the source files.
* Duplicate or stale transformed records: review the transform `latest.unique_key` behavior and verify the top-level `id` values remain stable across rescans.
* Certificate or readiness documents feel oversized: review large text fields such as PEM content and detailed reports before production retention policies are finalized.

## Performance and scaling

This package stores both the raw ingest stream and multiple transformed destination indices. Capacity planning should account for:

* Raw source event volume from TYCHON scans.
* Transform frequency, sync delay, and destination index growth.
* Retention requirements for both source and transformed data.
* Dashboard workloads that query multiple destination indices.

For broader scaling guidance, see Elastic's [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

These inputs can be used with this integration:

<details>
<summary>filestream</summary>

### Setup

For more details about the Filestream input settings, see the [Filebeat filestream input documentation](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-filestream).

### Collecting logs with filestream

Configure the input with one or more paths that point to TYCHON Quantum Command output files.

Default package path variables:

* Windows paths:
  * `C:\Program Files\Tychon\*.ndjson`
  * `C:\ProgramData\Tychon\*.ndjson`
* Linux paths:
  * `/var/log/tychon/*.ndjson`
  * `/opt/tychon/*.ndjson`
* Additional custom paths:
  * Any extra directories where TYCHON scan exports are written.

Optional package settings:

* `preserve_original_event`: copies the original message to `event.original` before ingest processing.
* `tags`: appends custom tags to collected events.

</details>

### API usage

This integration does not call a TYCHON vendor API. It is a file-based integration that ingests TYCHON Quantum Command output written to disk.

### Vendor documentation links

* [TYCHON Quantum Command product page](https://tychon.io/products/tychon/pqc-management-module/)
* [TYCHON support portal](https://support.tychon.io/)
* [Elastic Agent installation](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html)
* [Elastic filestream input reference](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-filestream)

### Data streams

#### `tychon_pqc`

The `tychon_pqc` data stream receives TYCHON Quantum Command output files collected through the `filestream` input. Source events are stored in the namespace-specific stream `logs-tychon_quantum_command.tychon_pqc-<namespace>` and then filtered by transforms using the `tychon.index` discriminator.

This stream can contain multiple TYCHON record families in one place, including inventory, certificates, ciphers, applications, crypto libraries, readiness, keystores, VPN client findings, IPsec tunnel findings, MACsec findings, installed application data, browser extension data, archives, and other supporting scan artifacts.

**Exported fields**

{{ fields "tychon_pqc" }}

**Example event**

{{ event "tychon_pqc" }}

### Data streams using ILM policies

This package does not define a custom package-level ILM policy. Apply retention and lifecycle controls according to your deployment standards for both the raw source stream and the transform destination indices.
