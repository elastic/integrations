# XM Cyber Integration

## Overview

[XM Cyber](https://www.xmcyber.com) is a **Continuous Threat Exposure Management (CTEM)** and attack path management platform. It continuously simulates attacker movement across hybrid environments including on-premises, cloud, and identity infrastructure — combining vulnerabilities, misconfigurations, and overly permissive access into prioritized attack paths that lead to **critical assets**.

This integration collects data from the XM Cyber REST API using scheduled polling. It provides visibility into your organization's security posture across your environment.

### Compatibility

The XM Cyber integration is compatible with the API version **1.0.0**.

### How it works

The integration uses the Elastic Agent CEL (Common Expression Language) input to poll the XM Cyber REST API on a configurable schedule. Each poll:

1. Authenticates with a two-step flow: exchanges the API key for a short-lived Bearer access token via `POST /api/auth`
2. Fetches data from the configured endpoint.
3. Emits each record as an individual event for ingestion and enrichment via the built-in ingest pipeline

## What data does this integration collect?

The XM Cyber integration collects the following types of data:

| Data stream | Description | Endpoint |
|---|---|---|
| `product` | **Product-level** aggregates from VRM: one event per software product with fleet-wide counts (devices where it appears, choke-point presence, affected critical assets, products critical assets at risk, vulnerability count), vendor, and reported operating systems. | `/api/v2/vrm/public/products` |

### Supported use cases

- **Software exposure across the fleet**: Rank products by `product_vulnerabilities`, `devices_found_on`, and `choke_points_found_on`, and slice by `product_operating_systems` to align remediation with platform mix.
- **Critical-asset risk from products**: Use `affected_critical_assets` and `products_critical_assets_at_risk` with vendor and OS context to prioritize patch and upgrade work.

## What do I need to use this integration?

- **XM Cyber tenant**: An active XM Cyber deployment with access to `https://<your-org>.clients.xmcyber.com`
- **API key**: An XM Cyber API key associated with a user holding at minimum the **Security Analyst** role. Create one in **Settings → API / Integrations** in your XM Cyber admin console (refer to the XM Cyber customer portal at https://customers.xmcyber.com for current navigation steps)
- **Elastic Agent**: Version 8.18+ or 9.0+ with Fleet enrollment

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Configure

1. In Kibana, navigate to **Fleet → Integrations** and search for **XM Cyber**
2. Click **Add XM Cyber**
3. Configure the integration settings:
   - **URL**: Your XM Cyber base URL, for example `https://your-org.clients.xmcyber.com`
   - **API Key**: Your XM Cyber API key.
   - **Interval**: How often to poll for new data (default: `24h`).
4. Select **Save and continue** to save the integration.

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **XM Cyber**, and verify the dashboard information is populated.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Troubleshooting

- **Authentication failures**: Verify the API key is valid and the URL includes the full `https://` prefix with no trailing slash
- **No data collected**: Check the Elastic Agent logs for CEL program errors. Ensure your XM Cyber user has the Security Analyst role and API access is enabled in your tenant settings
- **Rate limiting**: XM Cyber API rate limits are not publicly documented. If you observe HTTP 429 responses in agent logs, increase the collection interval

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Reference

### Product

#### Product fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| xm_cyber.product.affected_critical_assets | Affected critical assets count for this product. | long |
| xm_cyber.product.choke_points_found_on | Count of choke-point contexts where this product appears. | long |
| xm_cyber.product.devices_found_on | Number of devices where this product is installed. | long |
| xm_cyber.product.product_name | Product display name from the API. | keyword |
| xm_cyber.product.product_operating_systems | OS strings where the product is reported | keyword |
| xm_cyber.product.product_vulnerabilities | Vulnerability count associated with this product. | long |
| xm_cyber.product.products_critical_assets_at_risk | Critical assets at risk attributed to this product. | long |
| xm_cyber.product.vendor | Software vendor when present. | keyword |


### Example event

#### Product

An example event for `product` looks as following:

```json
{
    "@timestamp": "2026-07-01T15:33:52.609Z",
    "agent": {
        "ephemeral_id": "a3795845-fbb9-4b88-aaed-2a8e09ad0848",
        "id": "18ef6aa4-8616-4cd9-b863-9b4c16279260",
        "name": "elastic-agent-41139",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "xm_cyber.product",
        "namespace": "21831",
        "type": "logs"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "elastic_agent": {
        "id": "18ef6aa4-8616-4cd9-b863-9b4c16279260",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "xm_cyber.product",
        "ingested": "2026-07-01T15:33:55Z",
        "kind": "event",
        "original": "{\"affectedCriticalAssets\":2,\"chokePointsFoundOn\":0,\"devicesFoundOn\":2,\"productName\":\"wget\",\"productOperatingSystems\":[\"Linux sles 12.5 Server\"],\"productVulnerabilities\":1,\"productsCriticalAssetsAtRisk\":0,\"vendor\":null}"
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "xm_cyber-product"
    ],
    "xm_cyber": {
        "product": {
            "affected_critical_assets": 2,
            "choke_points_found_on": 0,
            "devices_found_on": 2,
            "product_name": "wget",
            "product_operating_systems": [
                "Linux sles 12.5 Server"
            ],
            "product_vulnerabilities": 1,
            "products_critical_assets_at_risk": 0
        }
    }
}
```

### Inputs used

These inputs can be used with this integration:
<details>
<summary>cel</summary>

## Setup

For more details about the CEL input settings, check the [Filebeat documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html).

Before configuring the CEL input, make sure you have:
- Network connectivity to the target API endpoint
- Valid authentication credentials (API keys, tokens, or certificates as required)
- Appropriate permissions to read from the target data source

### Collecting logs from CEL

To configure the CEL input, you must specify the `request.url` value pointing to the API endpoint. The interval parameter controls how frequently requests are made and is the primary way to balance data freshness with API rate limits and costs. Authentication is often configured through the `request.headers` section using the appropriate method for the service.

NOTE: To access the API service, make sure you have the necessary API credentials and that the Filebeat instance can reach the endpoint URL. Some services may require IP whitelisting or VPN access.

To collect logs via API endpoint, configure the following parameters:

- API Endpoint URL
- API credentials (tokens, keys, or username/password)
- Request interval (how often to fetch data)
</details>


### API usage

These XM Cyber REST API endpoints are used by this integration:

| Endpoint | Method | Data stream | Description |
|---|---|---|---|
| `/api/auth` | POST | all | Exchange API key for Bearer access token |
| `/api/refresh-token` | POST | all | Refresh an expired access token |
| `/api/v2/vrm/public/products` | GET | `product` | Paginated product-level exposure aggregates (counts and OS list per product) |
