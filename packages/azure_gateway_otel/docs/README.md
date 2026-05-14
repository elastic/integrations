# Azure Application Gateway OpenTelemetry Assets

Azure Application Gateway is a managed Layer 7 (HTTP/HTTPS) load balancer and reverse proxy that terminates client connections, evaluates routing rules, and forwards requests to backend pools, with an optional Web Application Firewall (WAF) capability.

These assets provide dashboards covering traffic, latency, errors, backend health, and WAF posture from `ApplicationGatewayAccessLog` and `ApplicationGatewayFirewallLog` records produced by the Azure encoding extension.

## Compatibility

The Azure Application Gateway OpenTelemetry assets have been tested with the OpenTelemetry Azure encoding extension (`azureencodingextension`).

Tested against:

- Azure Application Gateway v2 SKU (Standard_v2, WAF_v2)

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

### Prerequisites

You must enable diagnostic settings on your Azure Application Gateway and route the `ApplicationGatewayAccessLog` and `ApplicationGatewayFirewallLog` categories to a destination (Event Hub, Storage Account, or Log Analytics) that your forwarder can consume. The `ApplicationGatewayPerformanceLog` category is only emitted by the v1 SKU and is optional; the content pack does not depend on it.

The `azureencodingextension` decodes diagnostic log records into OpenTelemetry-native log records; no additional service-side configuration is required beyond enabling the diagnostic log categories.

### Configuration

Add your own setup details as per the EDOT Cloud Forwarder (ECF) used.

## Reference

### Logs

Refer to the [azureencodingextension](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/extension/encoding/azureencodingextension/README.md) documentation for details on the data produced by this encoding extension.

Records are written to the `logs-azure.application_gateway.otel-*` index pattern. Each record carries an `attributes.azure.category` discriminator (`ApplicationGatewayAccessLog`, `ApplicationGatewayFirewallLog`, or `ApplicationGatewayPerformanceLog`) which determines the available attribute set; queries should always filter by category before aggregating.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[Azure Application Gateway OTel] Overview** | Traffic, status, latency, and top entities for an Application Gateway from access log records. |
| **[Azure Application Gateway OTel] WAF** | WAF posture from firewall log records: match volume, action breakdown, top rulesets, rules, offenders, and policy scope. |
| **[Azure Application Gateway OTel] Backend Health** | Per-pool latency percentiles, backend status distribution, per-instance balance, and gateway-vs-backend latency split. |
