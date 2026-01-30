# On-Premises Billing Integration

Generates ESS Billing-compatible metrics for on-premises, ECE, and ECK deployments, enabling the Chargeback integration to work in non-cloud environments.

**mERU Cost Model** - Uses milli-ERUs (mERU) internally where 1 ERU = 1000 mERU, avoiding awkward fractional values while supporting deployments of any size.

## Features

- **Organization-level config**: Set total license cost, ERUs purchased, and ERU-to-RAM ratio
- **Flexible deployment config**: Configure via direct ERU input or RAM-based calculation
- **Clean internal values**: 0.25 ERU = 250 mERU, 5 ERU = 5000 mERU
- **Chargeback compatible**: Outputs to standard ESS Billing format

## Requirements

- Elastic Stack 9.2.0+
- Elasticsearch Integration (for Stack Monitoring data in `monitoring-indices`)

This integration enables the Chargeback integration (0.2.x+) to work on non-cloud deployments.

## Quick Setup

1. Install integration on monitoring cluster
2. Configure organization settings (license cost, total ERUs)
3. Configure each deployment with `deployment_erus` OR `node_count`/`ram_per_node_gb`
4. Create enrich policies and start billing transform

See full documentation after installation.

## Known Limitations

- **Single SKU per deployment**: Currently uses one SKU (`onprem-daily-{id}`) per deployment. When Chargeback adds SKU-level cost breakdown, this integration will need updates to support granular cost allocation (compute, storage, etc.).
