# Rapid7 InsightVM

## Overview

The [Rapid7 InsightVM](https://www.rapid7.com/products/insightvm/) integration allows users to monitor Asset and Vulnerability Events. Rapid7 InsightVM discovers risks across all your endpoints, cloud, and virtualized infrastructure. Prioritize risks and provide step-by-step directions to IT and DevOps for more efficient remediation. View your risk in real-time right from your dashboard. Measure and communicate progress on your program goals.

Use the Rapid7 InsightVM integration to collect and parse data from the REST APIs. Then visualize that data in Kibana.

## Data streams

The Rapid7 InsightVM integration collects two type of events: Asset and Vulnerability.

**Asset** is used to get details related to inventory, assessment, and summary details of assets that the user has access to. See more details in the API documentation [here](https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/searchIntegrationAssets).

**Vulnerability** is used to retrieve all vulnerabilities that can be assessed. See more details in the API documentation [here](https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/searchIntegrationVulnerabilities).

## Requirements

Elasticsearch is needed to store and search data, and Kibana is needed for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your hardware.

This module uses **InsightVM Cloud Integrations API v4**.

## Setup

### To collect data from the Rapid7 InsightVM APIs, follow the below steps:

1. Generate the platform API key to access all Rapid7 InsightVM APIs. For more details, see [Documentation](https://docs.rapid7.com/insight/managing-platform-api-keys).

## Logs Reference

### asset

This is the `asset` dataset.

#### Example

{{event "asset"}}

{{fields "asset"}}

### vulnerability

This is the `vulnerability` dataset.

#### Example

{{event "vulnerability"}}

{{fields "vulnerability"}}