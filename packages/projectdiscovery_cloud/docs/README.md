# ProjectDiscovery Cloud Integration

[![Version](https://img.shields.io/badge/version-0.1.1-blue.svg)](https://github.com/elastic/integrations)
[![License](https://img.shields.io/badge/license-Elastic--2.0-green.svg)](LICENSE.txt)

The ProjectDiscovery Cloud integration allows you to monitor and ingest vulnerability changelog events from [ProjectDiscovery Cloud](https://cloud.projectdiscovery.io) into Elasticsearch. ProjectDiscovery Cloud is an External Attack Surface Management (EASM) platform that continuously scans and monitors your external attack surface for security vulnerabilities using the Nuclei scanner.

## Overview

This integration collects vulnerability changelog events from the ProjectDiscovery Cloud API and ingests them into Elasticsearch with proper ECS (Elastic Common Schema) field mappings. This enables you to:

- **Monitor** vulnerability status changes in real-time
- **Track** security posture across your attack surface
- **Visualize** vulnerability trends in Kibana
- **Alert** on critical vulnerability changes
- **Investigate** security incidents with full context

For example, if you want to track when SSL/TLS vulnerabilities are detected or fixed on your infrastructure, this integration will automatically collect those events from ProjectDiscovery Cloud, normalize them to ECS format, and make them searchable in Elasticsearch.

## Features

- ✅ **Real-time ingestion** via ProjectDiscovery Cloud API
- ✅ **ECS-compliant** field mappings for standardized security data
- ✅ **Offset-based pagination** for reliable data collection
- ✅ **Vendor namespace preservation** for ProjectDiscovery-specific fields
- ✅ **Configurable collection intervals** and batch sizes
- ✅ **HTTP request tracing** for debugging
- ✅ **Comprehensive testing** with pipeline and system tests

## Data Streams

The ProjectDiscovery Cloud integration collects one type of data stream: **logs**.

### Vulnerability Changelogs (`changelogs`)

**Logs** help you keep a record of vulnerability status changes detected by ProjectDiscovery Cloud's Nuclei scanner.

The `changelogs` data stream collects changelog events including:
- Vulnerability status transitions (open → fixed, fixed → reopened, etc.)
- Vulnerability metadata (ID, severity, description)
- Scanner information (Nuclei template details)
- Target information (host, IP, port)
- Change event details (from/to values)

See more details in the [Logs Reference](#logs-reference) section.

## Requirements

### Elastic Stack

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

**Minimum versions:**
- Kibana: `^9.1.0`
- Elasticsearch: Compatible with Kibana version
- Elastic subscription: `basic`

### ProjectDiscovery Cloud

- Active ProjectDiscovery Cloud account
- API Key with read access to vulnerability changelogs
- Team ID associated with your ProjectDiscovery Cloud account

### Permissions

The API credentials must have permissions to:
- Read vulnerability changelog events (`GET /v1/scans/vuln/changelogs`)

## Setup

### Step 1: Obtain ProjectDiscovery Cloud Credentials

1. Log in to [ProjectDiscovery Cloud](https://cloud.projectdiscovery.io)
2. Navigate to **Settings** → **API Keys**
3. Create a new API key or use an existing one
4. Note your **Team ID** (found in your account settings)

### Step 2: Install the Integration

1. In Kibana, navigate to **Management** → **Integrations**
2. Search for "ProjectDiscovery Cloud"
3. Click **Add ProjectDiscovery Cloud**

### Step 3: Configure the Integration

Configure the following settings:

| Setting | Description | Default | Required |
|---------|-------------|---------|----------|
| **API Base URL** | ProjectDiscovery Cloud API endpoint | `https://api.projectdiscovery.io` | Yes |
| **API Key** | Your ProjectDiscovery Cloud API key | - | Yes |
| **Team ID** | Your ProjectDiscovery Cloud team ID | - | Yes |
| **Collection Interval** | How often to poll for new events | `5m` | Yes |
| **Batch Size** | Number of events per API request | `100` | Yes |
| **Time Window** | Filter events by time (e.g., `24h`, `7d`) | - | No |
| **HTTP Client Timeout** | Timeout for HTTP requests | `30s` | No |
| **Enable Request Tracer** | Enable detailed HTTP logging | `false` | No |

### Step 4: Deploy and Verify

1. Click **Save and Continue**
2. Add the integration to an agent policy
3. Deploy the agent policy to your Elastic Agent
4. Verify data ingestion in **Discover** by searching for `data_stream.dataset: "projectdiscovery_cloud.changelogs"`

For step-by-step instructions, see the [Getting started with Elastic Observability](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Configuration Details

### API Authentication

The integration authenticates with ProjectDiscovery Cloud using two HTTP headers:
- `X-API-Key`: Your API key
- `X-Team-Id`: Your team ID

Both headers are automatically set by the integration based on your configuration.

### Pagination

The integration uses **offset-based pagination** to collect all events:
- Initial request: `offset=0`
- Subsequent requests: `offset` increments by the number of events received
- Continues until no more events are returned

### HTTP Request Tracing

Enable request tracing for debugging:
1. Set **Enable Request Tracer** to `true`
2. Trace files are written to: `../../logs/cel/http-request-trace-*.ndjson`
3. Up to 5 backup files are kept

**⚠️ Security Warning:** Request tracing logs may contain sensitive data including API keys. Only enable for debugging and disable when done.

## Logs Reference

### Changelogs Data Stream

The `changelogs` data stream provides changelog events from ProjectDiscovery Cloud's vulnerability scanner.

#### Event Types

- **event.kind**: `event`
- **event.category**: `["vulnerability"]`
- **event.type**: `["info"]`

#### ECS Field Mappings

| ECS Field | Description | Type |
|-----------|-------------|------|
| `@timestamp` | Event timestamp (from `created_at`) | date |
| `event.module` | Always `projectdiscovery_cloud` | keyword |
| `event.dataset` | Always `projectdiscovery_cloud.changelogs` | keyword |
| `event.kind` | Always `event` | keyword |
| `event.category` | Always `["vulnerability"]` | keyword |
| `event.type` | Always `["info"]` | keyword |
| `vulnerability.id` | Unique vulnerability identifier | keyword |
| `vulnerability.status` | Current status (open, fixed, etc.) | keyword |
| `vulnerability.description` | Vulnerability description | text |
| `vulnerability.reference` | Reference URLs | keyword |
| `vulnerability.severity` | Severity level (low, medium, high, critical) | keyword |
| `vulnerability.scanner.vendor` | Always `ProjectDiscovery` | keyword |
| `vulnerability.scanner.type` | Always `nuclei` | keyword |
| `server.port` | Target server port | long |
| `message` | Human-readable event description | text |
| `tags` | Tags: `["projectdiscovery-cloud", "vulnerability", "changelogs", "forwarded"]` | keyword |

#### Vendor-Specific Fields

Additional fields in the `projectdiscovery.*` namespace:

| Field | Description | Type |
|-------|-------------|------|
| `projectdiscovery.target` | Target hostname | keyword |
| `projectdiscovery.vuln_hash` | Vulnerability hash | keyword |
| `projectdiscovery.scan_id` | Scan identifier | keyword |
| `projectdiscovery.template_url` | Nuclei template URL | keyword |
| `projectdiscovery.matcher_status` | Matcher status | boolean |
| `projectdiscovery.created_at` | Creation timestamp (optional) | date |
| `projectdiscovery.updated_at` | Update timestamp (optional) | date |
| `projectdiscovery.change_event` | Array of change objects | flattened |
| `projectdiscovery.event.*` | Full Nuclei event details | group |

**Note:** `projectdiscovery.created_at` and `projectdiscovery.updated_at` are only retained if the `preserve_duplicate_custom_fields` tag is set, as these values are also copied to `@timestamp`.

## License

This integration is licensed under the Elastic License 2.0.

---

**Version:** 0.1.1
