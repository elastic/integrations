# Google Cloud Integration

The Google Cloud integration collects and parses Google Cloud audit, VPC flow,
and firewall logs that have been exported from Stackdriver to a Google Pub/Sub topic sink.

## Logs

### Audit

This is the `audit` dataset.

{{event "audit"}}

{{fields "audit"}}

### Firewall

This is the `firewall` dataset.

{{event "firewall"}}

{{fields "firewall"}}

### VPC Flow

This is the `VPC Flow` dataset.

{{event "vpcflow"}}

{{fields "vpcflow"}}

### DNS

This is the `DNS` dataset.

{{event "dns"}}

{{fields "dns"}}
