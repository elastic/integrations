# Azure Activity Logs OpenTelemetry Assets

Azure Activity Logs provide a platform-level audit trail for Azure Resource Manager control plane operations, including resource creation, modification, deletion, and service health events.

This content pack provides dashboards, alert rules, and SLO templates for Azure Activity Logs collected via OpenTelemetry. It covers administrative operations, platform health signals, and security-sensitive actions.

## Compatibility

The Azure Activity Logs OpenTelemetry assets work with Azure Activity Log data forwarded through the [EDOT Cloud Forwarder (ECF) for Azure](https://www.elastic.co/docs/reference/opentelemetry/edot-cloud-forwarder/azure) using the `azureactivitylogs` encoding extension.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage
the Elastic Stack on your own hardware.

## Setup

### Prerequisites

No service-side configuration is required. Azure Activity Logs are available by default for all Azure subscriptions.

### Configuration

Refer to the [ECF for Azure documentation](https://www.elastic.co/docs/reference/opentelemetry/edot-cloud-forwarder/azure) for full setup instructions.

## Reference

### Logs

Refer to the [azureactivitylogs encoding extension](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/extension/encoding/azureactivitylogsextension/README.md) documentation for details on the data produced by this encoding extension.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[Azure Activity Logs OTel] Overview** | Platform-level audit logs for Azure Resource Manager control plane operations. Monitor operation volume, verb-level breakdown, failure rates, resource provider activity, top callers by identity, and sensitive operations. |
| **[Azure Activity Logs OTel] Administrative Operations** | Administrative Activity Log events: control plane CRUD operations, failures, operation duration, and mutation rates. Identify failed deployments and permission issues. |
| **[Azure Activity Logs OTel] Platform Health** | Azure platform health signals: ServiceHealth incidents, ResourceHealth status, and Advisor recommendations. Monitor external reliability factors. |

## Alert rules

| Alert | Trigger | Severity |
|-------|---------|----------|
| **[Azure Activity OTel] Change storm (high mutation rate)** | Spike in WRITE/DELETE/ACTION operations indicating a deployment storm or runaway automation | Warning |
| **[Azure Activity OTel] Failed administrative operations** | Administrative operations failing above normal threshold | Warning |
| **[Azure Activity OTel] Resource health degradation** | Resources transitioning to Unavailable or Degraded state | Warning |
| **[Azure Activity OTel] Role assignment write (privilege escalation)** | Role assignment changes detected, indicating potential privilege escalation | Warning |
| **[Azure Activity OTel] Security events** | Security-category events detected in the activity log | Warning |
| **[Azure Activity OTel] Sensitive key access** | Storage account listKeys or similar key-retrieval operations detected | Warning |
| **[Azure Activity OTel] Service health incident** | Azure ServiceHealth incident or outage affecting your subscription | Warning |

## SLO templates

| SLO | Target | Window | Description |
|-----|--------|--------|-------------|
| **[Azure Activity Logs OTel] Administrative operation success rate** | 99.5% | 30-day rolling | Tracks the success rate of Azure Resource Manager administrative operations, excluding in-progress Start/Started events. |
| **[Azure Activity Logs OTel] Administrative operation latency** | 99.5% | 30-day rolling | Tracks the average duration of Azure Resource Manager administrative operations, ensuring operation duration stays below 3 seconds. |
