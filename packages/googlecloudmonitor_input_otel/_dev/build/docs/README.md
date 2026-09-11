{{- generatedHeader }}
# Google Cloud Monitoring OpenTelemetry Input

## Overview

The Google Cloud Monitoring OpenTelemetry Input collects Google Cloud Monitoring metrics using the [Google Cloud Monitoring receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/googlecloudmonitoringreceiver) from the OpenTelemetry Collector.

This is a generic input package: you provide a GCP project ID and either an explicit list of Cloud Monitoring metric type names or filter expressions to select metric descriptors dynamically.

## How it works

This integration configures the Google Cloud Monitoring receiver in the EDOT (Elastic Distribution of OpenTelemetry) Collector, which:

1. Authenticates to Google Cloud using Application Default Credentials (ADC) found on the host running the collector. ADC is currently the only authentication mechanism this input supports.
2. Looks up the metric descriptor for each metric name you configure.
3. Polls the Cloud Monitoring API on a regular interval and retrieves the time series data for each configured metric.
4. Forwards the metrics to Elastic Agent, which ships them to Elasticsearch for indexing and visualization.

## Requirements

- A GCP project with the Cloud Monitoring API enabled.
- Application Default Credentials available to the collector process (see [Authentication](#authentication) below).
- An IAM principal granted the [`roles/monitoring.viewer`](https://cloud.google.com/iam/docs/roles-permissions/monitoring#monitoring.viewer) role on that project. The receiver needs `monitoring.metricDescriptors.list` to resolve metric descriptors and `monitoring.timeSeries.list` to read time series data. Both permissions are included in `roles/monitoring.viewer`, and a custom role granting only those two permissions is also sufficient.
- The specific Cloud Monitoring metric type names you want to collect (for example, `compute.googleapis.com/instance/cpu/utilization`). Browse available metrics with the [Metrics Explorer](https://cloud.google.com/monitoring/charts/metrics-selector) or the [`projects.metricDescriptors.list`](https://cloud.google.com/monitoring/api/ref_v3/rest/v3/projects.metricDescriptors/list) API.

## Configuration

### Core settings

| Setting | Description | Default |
|---|---|---|
| GCP Project ID | The GCP project ID to query Cloud Monitoring metrics from. | — |
| Metrics List | The Cloud Monitoring metric type names to collect. One time series query is issued per metric. | — |
| Collection Interval | How often the receiver polls Cloud Monitoring. | `300s` |

### Advanced settings

| Setting | Description | Default |
|---|---|---|
| Metric Descriptor Filters | Alternative to Metrics List: filter expressions used to look up metric descriptors dynamically instead of naming exact metric types. | — |
| Initial Delay | How long the receiver waits before starting. | `1s` |
| Timeout | Timeout for requests against the GCP Monitoring REST API. | `1m` |
| API Endpoint | Overrides the default `monitoring.googleapis.com:443` endpoint. Only needed for non-standard universe domains. | `monitoring.googleapis.com:443` |
| Universe Domain | The Google Cloud universe domain. Only needed for Sovereign Cloud regions. | `googleapis.com` |

Guidance:

- The receiver enforces a hard minimum **Collection Interval** of `60s`; lower values are rejected at startup. Be mindful of [Cloud Monitoring API quotas and costs](https://cloud.google.com/stackdriver/pricing#monitoring-costs) when choosing a low interval.
- At least one entry is required across **Metrics List** and **Metric Descriptor Filters** combined; the receiver rejects a configuration with neither.
- Each entry in **Metrics List** must be an exact Cloud Monitoring metric type name (for example, `compute.googleapis.com/instance/cpu/utilization`).
- Each entry in **Metric Descriptor Filters** (advanced) is a [metric descriptor filter expression](https://cloud.google.com/monitoring/api/v3/filters#metric-descriptor-filter) supporting only the `project` and `metric.type` filter objects (for example, `metric.type = starts_with("compute.googleapis.com/instance/")`). An entry cannot combine both a metric name and a filter.

## Authentication

For now, the only supported authentication mechanism is [Application Default Credentials (ADC)](https://cloud.google.com/docs/authentication/application-default-credentials), which the receiver resolves from the environment the collector process runs in. Fleet therefore exposes no credential fields for this input.

Provide ADC to the host running Elastic Agent using one of the following, in order of preference:

- **Workload identity** (GKE, Cloud Run, or another GCP compute service running the agent): credentials are supplied automatically.
- **A pre-provisioned service account key file**: set the `GOOGLE_APPLICATION_CREDENTIALS` environment variable on the Elastic Agent host to the path of a service-account JSON key file before the agent starts.
- **`gcloud auth application-default login`**: useful for development and testing, not recommended for production.

For the IAM role the credentials need, see [Requirements](#requirements).

## Metrics reference

For the full metric catalog, see the [Google Cloud Monitoring metrics list](https://cloud.google.com/monitoring/api/metrics).

## Troubleshooting

### No metrics appear

1. Confirm the collector process can resolve Application Default Credentials — check the Elastic Agent logs for `failed to find default credentials`.
2. Confirm the credentials have the `roles/monitoring.viewer` IAM role (or equivalent) on the configured project.
3. Confirm each entry under Metrics List is an exact, existing Cloud Monitoring metric type name (or each entry under Metric Descriptor Filters is a valid filter expression) — a typo results in an empty (not erroring) result for that metric.
4. Allow time for the first collection cycle. Cloud Monitoring metrics can have several minutes of ingest delay depending on the metric.

### Startup errors

1. `"collection_interval" must be not lower than...`: raise the Collection Interval to at least `60s`.
2. `missing required field "metrics_list" or its value is empty`: add at least one entry to Metrics List or Metric Descriptor Filters.
3. `fields "metric_name" and "metric_descriptor_filter" cannot both have value` / `cannot both be empty`: this points to a bug in this package's variable rendering rather than a configuration mistake. Each line in Metrics List or Metric Descriptor Filters always renders as exactly one selector type, so [open an issue](https://github.com/elastic/integrations/issues/new) if you see this.
4. `failed to find default credentials`: see [Authentication](#authentication).
5. `failed to retrieve metric descriptors data: context deadline exceeded`: the receiver could not reach the configured API Endpoint within Timeout. Check the endpoint host and port and confirm the Elastic Agent host can reach it.
6. `the configured universe domain (...) does not match the universe domain found in the credentials`: the Universe Domain does not match the credentials in use. Leave it at `googleapis.com` unless the agent runs in a Sovereign Cloud universe with credentials issued for that universe.

Entries 5 and 6 fail while the receiver is starting, which stops the whole collector rather than only this input. Any other OpenTelemetry integration in the same agent policy also stops collecting until the configuration is corrected.
