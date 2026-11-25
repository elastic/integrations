# On-Premises Billing Integration

Generates ESS Billing-compatible metrics for on-premises, ECE, and ECK deployments, enabling the **Chargeback** (`0.6.0+`) integration to allocate costs in non-cloud and hybrid environments.

> **Scope note:** Elastic Cloud Hosted (ECH) and Elastic Cloud Serverless deployments do **not** require this integration. Chargeback `0.6.0+` collects Elastic Cloud billing directly from Elastic Cloud APIs. Install **On-Premises Billing** only for self-managed, ECE, or ECK clusters.

**mERU Cost Model** - Uses milli-ERUs (mERU) internally where 1 ERU = 1000 mERU, avoiding awkward fractional values while supporting deployments of any size.

## Features

- **Organization-level config**: Set total license cost, ERUs purchased, and ERU-to-RAM ratio.
- **Flexible deployment config**: Configure via direct ERU input or RAM-based calculation.
- **Clean internal values**: 0.25 ERU = 250 mERU, 5 ERU = 5000 mERU.
- **Chargeback `0.6.0+` compatible**: Outputs `onprem_node` records to `metrics-ess_billing.billing-onprem`, discovers clusters from either Chargeback native usage telemetry (`metrics-chargeback.usage-*`) or Stack Monitoring (`monitoring-indices*`), and pairs with Chargeback's dedicated `onprem_unit_rate` setting for hybrid ECH + On-Premises estates.

## Requirements

- Elastic Stack `9.2.0+`
- Usage telemetry from **Chargeback `0.6.0+`** (`metrics-chargeback.usage-*`) and/or the **Elasticsearch** integration (`monitoring-indices*`, `*:monitoring-indices*`).

## Quick Setup

1. Install this integration on the monitoring cluster alongside **Chargeback** (`0.6.0+`).
2. Configure organization settings (license cost, total ERUs) in `onprem_billing_config`.
3. Configure each discovered deployment with `deployment_erus` or `node_count`/`ram_per_node_gb` and `daily_meru`.
4. Start the billing transform (no enrich policies required) and set `onprem_unit_rate` in the Chargeback Fleet integration policy.

See [docs/README.md](docs/README.md) for the full configuration guide.

## Known Limitations

- **Single SKU per deployment**: Uses one SKU (`onprem_node`) per deployment. Granular infrastructure SKUs (compute, storage, network) are not split in this version.
