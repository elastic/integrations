# Cribl

## Overview

The Cribl integration routes data from Cribl Stream into Elastic data streams by mapping Cribl source identifiers to Fleet datasets. This lets you keep Cribl as your data pipeline layer while using , dashboards, and detections for analytics and operations.

### Compatibility

This integration supports:

- Elastic Stack and Serverless projects with integration package support.
- Cribl Stream deployments that can use the **Elastic Cloud** or **Elasticsearch** destination.
- `logs` and `metrics` data stream types, with dynamic dataset and namespace routing.

### How it works

In Cribl Stream, you set a `_dataId` value on each event. In Fleet, you configure route mappings that map `_dataId` values to target datasets and optional namespaces. Cribl then sends events directly to Elastic using one of its Elastic destinations. The Cribl integration package provides routing configuration and data stream handling, while destination integrations provide parsing pipelines, dashboards, and assets.

## What data does this integration collect?

The Cribl integration collects and routes:

- `logs`: Log events forwarded from Cribl to Elastic data streams.
- `metrics`: Metric events forwarded from Cribl to Elastic data streams.

Use this integration when you want centralized routing and processing in Cribl, while keeping Elastic integration assets for downstream analysis.

## What do I need to use this integration?

To use this integration, you need:

- An Elastic deployment and access to Fleet in Kibana.
- Cribl Stream with permission to configure sources and destinations.
- An Elastic API key for the Cribl destination.
- Index privileges that include at least `auto_configure` and `write` for target `logs-*` and `metrics-*` patterns.

## How do I deploy this integration?

For step-by-step instructions about installing integrations, refer to [Getting started](https://www.elastic.co/guide/en/starting-with-the-elasticsearch-platform-and-its-solutions/current/getting-started-observability.html).

### Onboard and configure

1. Install destination integration assets in Fleet.
   - In Kibana, go to the **Integrations** page.
   - Install the integration assets for the datasets you plan to route (for example, Cisco ASA).

2. Configure `_dataId` in Cribl sources.
   - In Cribl Stream, add a `_dataId` field that identifies the target dataset mapping.
   - For more information, see [Cribl data onboarding](https://docs.cribl.io/stream/data-onboarding/).

3. Configure route mappings in the Cribl integration policy in Fleet.
   - Map each `_dataId` value to a target data stream dataset.
   - Optionally set a namespace. If omitted, `default` is used.
   - The Cribl integration does not require Elastic Agent, but Fleet policy configuration is still required.

4. Configure the Elastic destination in Cribl.
   - Use either [Elastic Cloud destination](https://docs.cribl.io/stream/destinations-elastic-cloud/) or [Elasticsearch destination](https://docs.cribl.io/stream/destinations-elastic/).
   - Set **Cloud ID** (Elastic Cloud) or **Bulk API URLs** (self-managed Elasticsearch).
   - Set **Index or Data Stream** based on event type:
     - `logs-cribl-default` for logs
     - `metrics-cribl-default` for metrics
   - Set **API key** to a Base64-encoded Elastic API key value.

### Validation

After deployment:

1. Send test events from Cribl.
2. In Kibana, open **Discover** and confirm documents in the expected `logs-*` or `metrics-*` data streams.
3. Verify dataset and namespace values match the `_dataId` route mappings.

## Troubleshooting

- No data in Elastic:
  - Verify destination connectivity (**Cloud ID** or **Bulk API URLs**).
  - Confirm API key privileges include `auto_configure` and `write`.
- Data lands in unexpected data streams:
  - Check `_dataId` values in Cribl events.
  - Check route mappings in the Cribl integration policy.
- Destination integration dashboards are empty:
  - Confirm corresponding destination integration assets are installed in Fleet.
  - Confirm routed dataset names match what those integration assets expect.

## Performance and scaling

- Use Cribl worker groups and horizontal scaling to handle higher event throughput.
- Tune batching, queueing, and backpressure settings in Cribl before increasing destination concurrency.
- Separate high-volume logs and metrics routes so you can scale and troubleshoot independently.
- Monitor ingestion rate and bulk response errors in both Cribl and Elastic to identify bottlenecks early.

## Reference

### Logs

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |


### Metrics

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
