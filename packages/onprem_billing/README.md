# On-Premises Billing Integration

Generates ESS Billing-compatible metrics for on-premises, ECE, and ECK deployments, enabling the Chargeback integration to work in non-cloud environments.

**Fixed Daily ECU Model** - each deployment is assigned a configurable daily ECU value.

## Requirements

- Elastic Stack 9.2.0+
- Elasticsearch Integration (for Stack Monitoring data in `monitoring-indices`)

This integration enables the Chargeback integration (0.2.x+) to work on non-cloud deployments.

## Quick Setup

1. Install integration on monitoring cluster
2. Configure deployments with `daily_ecu` and `deployment_tags`
3. Create enrich policy and start billing transform

See full documentation after installation.

## Known Limitations

- **Single SKU per deployment**: Currently uses one SKU (`onprem-daily-{id}`) per deployment. When Chargeback adds SKU-level cost breakdown, this integration will need updates to support granular cost allocation (compute, storage, etc.).
