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

### Vulnerability Changelogs (`vulnerability`)

**Logs** help you keep a record of vulnerability status changes detected by ProjectDiscovery Cloud's Nuclei scanner.

The `vulnerability` data stream collects changelog events including:
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
- Elastic subscription: `platinum`

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
| **Time Window** | Filter events by time (e.g., `last_day`) | - | No |
| **HTTP Client Timeout** | Timeout for HTTP requests | `10m` | No |
| **Enable Request Tracer** | Enable detailed HTTP logging | `false` | No |

### Step 4: Deploy and Verify

1. Click **Save and Continue**
2. Add the integration to an agent policy
3. Deploy the agent policy to your Elastic Agent
4. Verify data ingestion in **Discover** by searching for `data_stream.dataset: "projectdiscovery_cloud.vulnerability"`

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
2. Trace files are written to: `../../logs/httpjson/http-request-trace-*.ndjson`
3. Up to 5 backup files are kept

## Logs Reference

### Vulnerability Data Stream

The `vulnerability` data stream provides changelog events from ProjectDiscovery Cloud's vulnerability scanner.

#### Event Types

- **event.kind**: `event`
- **event.category**: `["vulnerability"]`
- **event.type**: `["change"]`

#### ECS Field Mappings

| ECS Field | Description | Type |
|-----------|-------------|------|
| `@timestamp` | Event timestamp (from `created_at`) | date |
| `event.module` | Always `projectdiscovery_cloud` | keyword |
| `event.dataset` | Always `projectdiscovery_cloud.vulnerability` | keyword |
| `event.kind` | Always `event` | keyword |
| `event.category` | Always `["vulnerability"]` | keyword |
| `event.type` | Always `["change"]` | keyword |
| `vulnerability.id` | Unique vulnerability identifier | keyword |
| `vulnerability.status` | Current status (open, fixed, etc.) | keyword |
| `vulnerability.description` | Vulnerability description | text |
| `vulnerability.reference` | Reference URLs | keyword |
| `vulnerability.severity` | Severity level (low, medium, high, critical) | keyword |
| `vulnerability.scanner.vendor` | Always `ProjectDiscovery` | keyword |
| `vulnerability.scanner.type` | Always `nuclei` | keyword |
| `server.port` | Target server port | long |
| `input.type` | Always `httpjson` | keyword |
| `message` | Human-readable event description | text |
| `tags` | Tags: `["projectdiscovery-cloud", "vulnerability", "forwarded"]` | keyword |

#### Vendor-Specific Fields

Additional fields in the `projectdiscovery.*` namespace:

| Field | Description | Type |
|-------|-------------|------|
| `projectdiscovery.target` | Target hostname | keyword |
| `projectdiscovery.vuln_hash` | Vulnerability hash | keyword |
| `projectdiscovery.scan_id` | Scan identifier | keyword |
| `projectdiscovery.template_url` | Nuclei template URL | keyword |
| `projectdiscovery.matcher_status` | Matcher status | boolean |
| `projectdiscovery.created_at` | Creation timestamp | date |
| `projectdiscovery.updated_at` | Update timestamp | date |
| `projectdiscovery.change_event` | Array of change objects | flattened |
| `projectdiscovery.event.*` | Full Nuclei event details | group |

#### Example Event

An example event for `vulnerability` looks as follows:

```json
{
  "@timestamp": "2025-08-26T03:41:56.388431Z",
  "event": {
    "kind": "event",
    "category": ["vulnerability"],
    "type": ["change"],
    "module": "projectdiscovery_cloud",
    "dataset": "projectdiscovery_cloud.vulnerability"
  },
  "vulnerability": {
    "id": "d2c8nugviq0c9cusl19g",
    "status": "fixed",
    "description": "A root certificate is a digital certificate issued by a trusted certificate authority...",
    "reference": [
      "https://www.sslmarket.com/ssl/trusted-and-untrusted-certificate",
      "https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/ssl-untrusted-root-certificate/"
    ],
    "severity": "low",
    "scanner": {
      "vendor": "ProjectDiscovery",
      "type": "nuclei"
    }
  },
  "server": {
    "port": 80
  },
  "input": {
    "type": "httpjson"
  },
  "message": "ProjectDiscovery vulnerability changelog: d2c8nugviq0c9cusl19g status changed to fixed",
  "tags": ["projectdiscovery-cloud", "vulnerability", "forwarded"],
  "projectdiscovery": {
    "target": "abc.us-east-1.aws.found.io",
    "vuln_hash": "0fc00913410675e57934492d761faf71",
    "scan_id": "xyz",
    "template_url": "https://cloud.projectdiscovery.io/public/untrusted-root-certificate",
    "matcher_status": false,
    "created_at": "2025-08-26T03:41:56.388431",
    "updated_at": "2025-08-26T03:41:56.388431",
    "change_event": [
      {"from": "open", "name": "vuln_status", "to": "fixed"},
      {"from": true, "name": "matcher_status", "to": false}
    ],
    "event": {
      "host": "abc.us-east-1.aws.found.io",
      "ip": "175.16.199.1",
      "port": "80",
      "type": "ssl",
      "template-id": "untrusted-root-certificate",
      "info": {
        "name": "Untrusted Root Certificate - Detect",
        "severity": "low",
        "author": ["pussycat0x"],
        "tags": ["ssl", "tls", "untrusted"]
      }
    }
  },
  "data_stream": {
    "type": "logs",
    "dataset": "projectdiscovery_cloud.vulnerability",
    "namespace": "default"
  }
}
```

## Testing

The integration includes comprehensive testing capabilities for both pipeline processing and end-to-end system functionality.

### Prerequisites

Install the Elastic Package tool:

```bash
# Install elastic-package CLI
go install github.com/elastic/elastic-package@latest

# Verify installation
elastic-package version
```

### Pipeline Tests

Pipeline tests validate that the ingest pipeline correctly transforms raw API responses into ECS-formatted documents.

**Test data location:** `data_stream/vulnerability/_dev/test/pipeline/test-events.json`

**Run pipeline tests:**

```bash
# From the integration root directory
elastic-package test pipeline -v
```

**What it tests:**
- JSON parsing from the `message` field
- ECS field mappings (`vulnerability.*`, `event.*`, etc.)
- Vendor namespace preservation (`projectdiscovery.*`)
- Timestamp parsing from `created_at`
- Port type conversion to `long`
- Message field transformation

**Expected output:**
```
✓ Pipeline test passed: All events processed correctly
```

### System Tests

System tests perform end-to-end validation using a Go-based mock API server that simulates the ProjectDiscovery Cloud API.

**Test configurations:**
- `test-default-config.yml` - Standard collection test
- `test-pagination-config.yml` - Pagination behavior test

#### Running System Tests

**Option 1: Standard test (auto-cleanup)**

```bash
# From the integration root directory
elastic-package test system -v
```

**Option 2: Test with data inspection (recommended)**

Use the provided shell script to run tests with a 5-minute cleanup delay, allowing you to inspect ingested data:

```bash
# Run system test with deferred cleanup
./run-system-test-with-data-inspection.sh
```

This script:
1. Runs the full system test suite
2. Keeps the test environment running for 5 minutes
3. Provides example `curl` commands to inspect ingested data
4. Automatically cleans up after 5 minutes (or press Ctrl+C to keep data)

**What it tests:**
- Full integration with mock API server
- HTTP authentication headers
- Offset-based pagination
- Data ingestion into Elasticsearch
- ECS field validation
- Index template creation

**Expected output:**
```
🧪 Running system tests with deferred cleanup...
⏰ Data will be kept for 5 minutes after tests complete

[elastic-package] Running test cases for vulnerability...
✓ test-default-config.yml: PASS (39s)
✓ test-pagination-config.yml: PASS (38s)

📊 Test complete! Data is still available for inspection.
```

#### Viewing Ingested Data

While tests are running (with deferred cleanup), you can view ingested data using the provided script:

```bash
# View all ingested vulnerability documents
./view-ingested-data.sh
```

This script queries Elasticsearch and displays:
- Summary of all indexed documents with key fields
- One full document example (saved to `/tmp/ingested-sample.json`)
- Total document count

**Manual inspection commands:**

```bash
# View all documents
curl -sk -u elastic:changeme \
  'https://127.0.0.1:9200/logs-projectdiscovery_cloud.vulnerability*/_search?size=10&pretty'

# View latest document source
curl -sk -u elastic:changeme \
  'https://127.0.0.1:9200/logs-projectdiscovery_cloud.vulnerability*/_search?size=1&sort=@timestamp:desc' \
  | jq '.hits.hits[0]._source'

# Count total documents
curl -sk -u elastic:changeme \
  'https://127.0.0.1:9200/logs-projectdiscovery_cloud.vulnerability*/_count' \
  | jq

# View specific fields
curl -sk -u elastic:changeme \
  'https://127.0.0.1:9200/logs-projectdiscovery_cloud.vulnerability*/_search?size=1' \
  | jq '.hits.hits[0]._source | {vulnerability, event, message}'
```

### Test Data

The integration uses sample vulnerability changelog events based on real ProjectDiscovery API responses:

- **Event 1:** SSL untrusted root certificate vulnerability (status: `fixed`)
- **Event 2:** SSL untrusted root certificate vulnerability (status: `open`)

Both events include:
- Change events (status transitions)
- Full Nuclei scan metadata
- Target information
- Template details

### Troubleshooting Tests

**Pipeline test failures:**
```bash
# View the actual vs expected output
elastic-package test pipeline -v --report-format human
```

**System test failures:**
```bash
# Enable request tracing in test config
# Edit data_stream/vulnerability/_dev/test/system/test-default-config.yml
# Set enable_request_tracer: true

# Run with verbose output
elastic-package test system -v

# Check trace logs
cat ../../logs/httpjson/http-request-trace-*.ndjson | jq
```

**View mock server logs:**
```bash
# While system tests are running
docker logs -f elastic-package-service-vulnerability-1
```

## Architecture

### Components

1. **HTTPJSON Input** (`data_stream/vulnerability/agent/stream/stream.yml.hbs`)
   - Polls ProjectDiscovery Cloud API every `interval`
   - Handles authentication via headers
   - Manages offset-based pagination
   - Splits response array into individual events

2. **Ingest Pipeline** (`data_stream/vulnerability/elasticsearch/ingest_pipeline/default.yml`)
   - Parses JSON from `message` field
   - Maps fields to ECS schema
   - Preserves vendor-specific data in `projectdiscovery.*` namespace
   - Sets enriched message field

3. **Field Definitions** (`data_stream/vulnerability/fields/*.yml`)
   - ECS field definitions (`ecs.yml`)
   - Vendor-specific field definitions (`fields.yml`)
   - Base field definitions (`base-fields.yml`)

4. **Mock API Server** (`data_stream/vulnerability/_dev/deploy/docker/main.go`)
   - Go-based HTTP server for testing
   - Simulates ProjectDiscovery Cloud API endpoints
   - Returns sample vulnerability changelog events
   - Supports pagination with offset parameter

## Development

### Building the Package

```bash
# Build the integration package
elastic-package build

# Output: build/packages/projectdiscovery_cloud/0.1.1/
```

### Formatting

```bash
# Format integration files
elastic-package format
```

### Linting

```bash
# Lint integration files
elastic-package lint
```

### Local Installation

```bash
# Install to local Kibana (requires running Elastic Stack)
elastic-package install
```

## Support

- **Documentation:** [Elastic Integrations](https://www.elastic.co/guide/en/integrations/current/index.html)
- **Issues:** [GitHub Issues](https://github.com/elastic/integrations/issues)
- **Forum:** [Elastic Discuss](https://discuss.elastic.co/c/observability/integrations/)

## License

This integration is licensed under the Elastic License 2.0. See [LICENSE.txt](../LICENSE.txt) for details.

## Changelog

See [changelog.yml](../changelog.yml) for version history and changes.

---

**Version:** 0.1.1  
**Last Updated:** 2025-01-22
