# Bitsight Integration

This integration collects data from the Bitsight API.

## Data Streams

- **bitsight.vulnerability** — Pulls vulnerabilities with the related company exposures, and evidence items.

## Requirements

- Elasticsearch & Kibana ≥ 8.17.3
- Bitsight API Token

## Setup

1. Install the integration in Kibana.
2. Provide the Bitsight API Base URL and API Token.
3. Configure the polling interval, batch size, and lookback interval for initial data collection.

## Logs

### Vulnerability

This is the `vulnerability` dataset.

{{event "vulnerability"}}

{{fields "vulnerability"}}