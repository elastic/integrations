{{- generatedHeader }}
# Trivy Integration for Elastic

## Overview

The Trivy integration collects vulnerability findings from Trivy scan reports and maps them to ECS vulnerability fields. It reads flattened Trivy JSON reports stored as NDJSON files, with one vulnerability finding per line, using the filestream input.

### Compatibility

This integration is compatible with Trivy 0.68 and later scan reports in JSON format (`schema_version: 2`). The reports must be flattened to one finding per line before they are collected, as described in the Set up steps in Trivy section. The integration has been tested against image scan and Kubernetes scan reports.

### How it works

Trivy writes a JSON report per scanned artifact. You convert that report into NDJSON, one line per vulnerability finding, and store it on disk. Elastic Agent reads the NDJSON files with the filestream input, and the ingest pipeline parses each line and maps the Trivy fields to ECS fields, including `vulnerability.id`, `vulnerability.severity`, `vulnerability.score.base`, and `vulnerability.package.*`. The original Trivy keys are preserved alongside the ECS fields for full fidelity.

## What data does this integration collect?

The Trivy integration collects vulnerability findings, one per event. Each event describes:

* The vulnerability itself (CVE or advisory ID, severity, CVSS score, description, references, fix status)
* The affected package (name, installed version, fixed version, path or lockfile)
* The scanned artifact (container image reference, image ID, repository tags, operating system)
* The scan context (scan time, Trivy version, and for Kubernetes scans the cluster, namespace, and workload)

### Supported use cases

* Vulnerability management dashboards and the Elastic Security Findings page
* Continuous scanning pipelines that export Trivy reports to disk on CI runners, container hosts, or Kubernetes nodes
* Correlating findings with the host or workload that carries them

## What do I need to use this integration?

* Elastic Agent 8.19 or 9.1 and later
* Trivy 0.68 or later
* Write access to a directory on the host where flattened NDJSON report files are stored

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to read the report files from disk and ship the data to Elastic, where the events are processed by the integration's ingest pipeline.

### Set up steps in trivy

Run a Trivy scan with JSON output, then flatten the report to NDJSON with one finding per line. The following example scans a container image:

```bash
trivy image --format json registry.example.com/team-a/webapp:13 > report.json

jq -c '
  .Results[] as $r
  | ($r.Vulnerabilities // [])[]
  | {
      scan: {
        time: (.Metadata.scan_time // now | todate),
        schema_version: .SchemaVersion,
        trivy_version: .Metadata.Version
      },
      resource: null,
      artifact: (.Metadata | {ArtifactName, ArtifactType, OS, ImageID, RepoTags, RepoDigests, Reference}),
      result: {Target: $r.Target, Class: $r.Class, Type: $r.Type},
      vulnerability: .
    }
' report.json >> /var/log/trivy/trivy-vulnerability-image.ndjson
```

For Kubernetes scans, `trivy k8s --format json` produces one report per workload. Add the `--cluster-name` value and the workload metadata from the report to the `scan` and `resource` objects so findings can be attributed to a namespace and deployment.

Rotate or size the NDJSON files as needed. Elastic Agent tracks read offsets per file, so appending to an existing file is safe.

#### Vendor resources

* [Trivy documentation](https://trivy.dev/latest/)
* [Trivy Kubernetes scans](https://trivy.dev/latest/cmd/trivy-kubernetes/)

### Set up steps in Kibana

1. In Kibana, go to Integrations and search for Trivy.
2. Add the Trivy integration and create a policy with the Trivy scan reports input.
3. Set Paths to the glob of the flattened NDJSON report files, for example `/var/log/trivy/*.ndjson`.
4. Optionally enable Preserve original event to store the raw finding line in `event.original`. Each finding is typically several kilobytes, so this increases storage for full cluster scans.
5. Assign the policy to the hosts where the report files are stored.

### Validation

After the agent applies the policy, check that documents arrive in the `logs-trivy.vulnerability-*` data stream. A typical finding has `vulnerability.id` set to a CVE identifier, `vulnerability.severity` populated, and `vulnerability.package.name` matching the scanned package. The raw Trivy keys, for example `vulnerability.VulnerabilityID` and `artifact.Reference`, are available in the same document.

#### Support for the Elastic Vulnerability Findings page

The integration adds support for the [Elastic Cloud Security workflow](https://www.elastic.co/docs/solutions/security/cloud/ingest-third-party-cloud-security-data#_ingest_third_party_security_posture_and_vulnerability_data), which displays findings in the Elastic [Findings page](https://www.elastic.co/docs/solutions/security/cloud/findings-page-3). An [Elastic Latest Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview) copies the latest vulnerability findings from source indices matching the pattern `logs-trivy.vulnerability-*` into destination indices matching the pattern `security_solution-trivy.vulnerability_latest-*`. The Findings page displays vulnerabilities based on the destination indices.

For this to work, findings must carry the ECS fields the workflow groups and deduplicates on: `vulnerability.id`, `package.name`, `package.version`, `package.path`, `package.fixed_version`, and `resource.id`. The ingest pipeline derives `resource.id` from the Kubernetes workload for cluster scans (cluster, namespace, kind, and name) and from the image reference or artifact name otherwise, so flattened reports should keep the `resource` and `artifact` objects of the Trivy report intact.

The transform runs every 5 minutes and keeps 90 days of findings. Findings older than 90 days or documents with `error.message` set are excluded.

## Troubleshooting

- No data is being collected: Verify the Paths glob matches the report files and that Elastic Agent has read permission on the directory.
- Documents arrive but ECS fields are empty: Verify the report was flattened with the `vulnerability` key at the top level of each line. The pipeline maps from `vulnerability.Severity`, `vulnerability.PkgName`, and similar Trivy keys.
- Findings land in the wrong data stream: The `data_stream.dataset` of each document is fixed to `trivy.vulnerability` by the integration.

## Performance and scaling

Full Kubernetes cluster scans can produce hundreds of thousands of findings per run. Prefer appending scan output to rotating files over rewriting entire files, and keep `preserve_original_event` disabled unless raw lines are required. For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used
{{ inputDocs }}

### Vendor documentation links

* [Trivy documentation](https://trivy.dev/latest/)
* [Trivy JSON output examples](https://trivy.dev/latest/docs/configuration/reporting/)

### Data streams

#### vulnerability

The `vulnerability` data stream provides vulnerability findings from Trivy scan reports, one finding per event.

##### vulnerability fields
{{ fields "vulnerability" }}

##### vulnerability sample event
{{ event "vulnerability" }}

{{ ilm }}

{{ transform }}
