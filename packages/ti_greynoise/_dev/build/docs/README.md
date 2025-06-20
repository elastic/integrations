# GreyNoise

## Overview

[GreyNoise](https://www.greynoise.io/) is a cybersecurity platform that helps security teams filter out "internet noise" — background internet scanning activity that's not necessarily targeted or malicious. It collects, analyzes, and labels massive amounts of data from internet-wide scans, typically originating from bots, security researchers, or compromised systems.

## Prerequisites for GreyNoise

Customers must have access to the **Enterprise API** to fetch data from GreyNoise. You can verify your API key access [here](https://viz.greynoise.io/account/api-key).

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### To Collect Logs Through REST API

1. After logging in to GreyNoise, navigate to your [account page](https://viz.greynoise.io/account/api-key).
2. Click "View API Key" to display and copy your unique API key.

### Enabling the Integration in Elastic

1. In Kibana, go to **Management > Integrations**.
2. In the "Search for integrations" search bar, type **GreyNoise**.
3. Click the **GreyNoise** integration from the search results.
4. Click the **Add GreyNoise** button to add the integration.
5. While adding the integration, provide the following details to collect logs via REST API:
   - API Key
   - Interval
   - (Optional) Query for custom query filtering
6. Click **Save and Continue** to save the integration.

**Note:** The "last_seen" field should not be included in the query as it is predefined with a fixed value of "1d".

## Transforming Data for Up-to-Date Insights

To keep the collected data up to date, **Transforms** are used.

You can view transforms by navigating to **Management > Stack Management > Transforms**.

Here, you can see continuously running transforms and view the latest transformed GreyNoise data in the **Discover** section.

The `labels.is_transform_source` field indicates log origin:
- **False** for transformed index
- **True** for source index

Currently, one transform is running for the IP datastream:

| Transform Name | Description |
|----------------|-------------|
| IP Transform (ID: `logs-ti_greynoise.ip`) | Keeps IP entity type data up to date |

For example:
- The query `event.module: ti_greynoise and labels.is_transform_source: true` shows logs from the **source index**
- The query `event.module: ti_greynoise and labels.is_transform_source: false` shows logs from the **transformed index**

A **retention policy** removes data older than the default retention period. For more details, refer to the [Retention Policy Documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/put-transform.html#:~:text=to%20false.-,retention_policy,-(Optional%2C%20object)%20Defines).

In this integration, the IP data stream has a default **retention period of 7 days**.

## Troubleshooting

1. If you experience latency issues during data collection, consider increasing the `HTTP Client Timeout` configuration parameter.
2. If server-side errors occur, consider reducing the `Page Size` configuration parameter.
   **Note:** Avoid setting the `Page Size` too low, as this may increase the number of API requests, potentially causing processing issues.
3. If events are not appearing in the transformed index, check if transforms are running without errors. For issues, refer to [Troubleshooting transforms](https://www.elastic.co/guide/en/elasticsearch/reference/current/transform-troubleshooting.html).

## Logs Reference

### IP

This is the `IP` dataset. It uses the [GNQL Endpoint](https://docs.greynoise.io/reference/gnqlquery-1) to fetch data from GreyNoise with "last_seen:1d". It uses version v3 of the API to collect indicators. Currently, the [Triage](https://docs.greynoise.io/docs/intelligence-module-triage) and [Business Services](https://docs.greynoise.io/docs/intelligence-module-business-services) Intelligence Modules are being collected through this data stream.

#### Example

{{event "ip"}}

{{fields "ip"}}
