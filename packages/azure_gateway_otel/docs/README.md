# Azure Application Gateway OpenTelemetry Assets

Azure Application Gateway is a managed Layer 7 load balancer and reverse proxy that terminates TLS, routes HTTP/HTTPS traffic to backend pools, and optionally evaluates each request against a Web Application Firewall (WAF) policy.

These assets provide dashboards, alert rules, and SLO templates for Azure Application Gateway resource logs (Access, Firewall, and Performance) ingested via the OpenTelemetry `azureencodingextension`, covering traffic, latency, error rates, backend health, and WAF activity.

## Compatibility

The Azure Application Gateway OpenTelemetry assets have been tested with the OpenTelemetry `azureencodingextension`.

The assets target Azure Application Gateway resource logs from both v1 and v2 SKUs. Performance log panels and backend host count signals apply to v1 SKU only; v2 SKU is supported through Access and Firewall logs.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

### Prerequisites

You must enable Azure Diagnostic Settings on each Application Gateway resource and route the following log categories to the destination consumed by your EDOT Cloud Forwarder:

- `ApplicationGatewayAccessLog`
- `ApplicationGatewayFirewallLog` (when a WAF policy is attached)
- `ApplicationGatewayPerformanceLog` (v1 SKU only)

The Firewall log is only produced when a WAF policy is attached to the gateway, a listener, or a path location. The Performance log is only produced by v1 SKU gateways; v2 SKU resources will not emit it.

Ensure the gateway's managed identity (or the credentials configured on the diagnostic destination) has permission to write to the storage account, Event Hub, or Log Analytics workspace that your forwarder reads from.

### Configuration

Add your own setup details as per the EDOT Cloud Forwarder (ECF) used.

## Reference

### Logs

Refer to the [Azure encoding extension](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/extension/encoding/azureencodingextension/README.md) documentation for details on the resource log data produced by this encoding extension.

Each Application Gateway resource log record is translated into an OTel log document and written to `logs-azure.application_gateway.otel-default`. Records are discriminated by `attributes.azure.category`, which takes one of `ApplicationGatewayAccessLog`, `ApplicationGatewayFirewallLog`, or `ApplicationGatewayPerformanceLog`. The `attributes.azure.service.request.id` field joins an Access log entry to one or more Firewall log entries for the same request.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[Azure Application Gateway OTel] Overview** | Traffic, latency, and error overview for Azure Application Gateway access logs. |
| **[Azure Application Gateway OTel] Backend Health** | Backend pool latency, status, and AGW-vs-backend latency split for Azure Application Gateway. |
| **[Azure Application Gateway OTel] WAF** | Web Application Firewall activity for Azure Application Gateway: rule matches, actions, offending clients. |

## Alert rules

| Alert | Trigger | Severity |
|-------|---------|----------|
| **[Azure Application Gateway OTel] High backend pool 5xx rate** | A backend pool returns HTTP 5xx for more than 5% of requests that reached the backend over a 15-minute window. | Critical |
| **[Azure Application Gateway OTel] AGW-originated 5xx rate** | The gateway returns HTTP 5xx without reaching a backend above 1% of total requests over a 15-minute window. | High |
| **[Azure Application Gateway OTel] Listener p95 latency regression** | Client-perceived p95 latency at a listener exceeds 2 seconds over a 15-minute window. | High |
| **[Azure Application Gateway OTel] No healthy backend or upstream error** | `ERRORINFO_NO_HEALTHY_BACKEND` or `ERRORINFO_UPSTREAM_*` reason codes appear in Access logs over a 15-minute window. | Critical |
| **[Azure Application Gateway OTel] WAF attack concentration from client IP** | A single client IP triggers a large number of attack-category WAF rule matches over a 15-minute window. | Medium |

## SLO templates

| SLO | Target | Window | Description |
|-----|--------|--------|-------------|
| **[Azure Application Gateway OTel] Gateway availability 99.5% rolling 30 days** | 99.5% | 30-day rolling | Tracks the share of requests for which the gateway returned a status code below 500 to the client. |
| **[Azure Application Gateway OTel] Gateway latency under 1s 99.5% rolling 30 days** | 99.5% | 30-day rolling | Tracks the share of requests for which the total gateway processing time was below 1 second. |
