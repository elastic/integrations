# GreyNoise

## Overview

[GreyNoise](https://www.greynoise.io/) is a cybersecurity platform that helps security teams filter out "internet noise" — essentially, background internet scanning activity that’s not necessarily targeted or malicious. It collects, analyzes, and labels massive amounts of data from internet-wide scans, often coming from bots, security researchers, or compromised systems.

## Pre-requisites for GreyNoise

Customers must have access to **Enterprise API** in order to fetch data from GreyNoise. Customers can check their API key access [here](https://viz.greynoise.io/account/api-key).

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data through the REST API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent. For more information, refer to the Elastic Agent [installation guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

## Setup

### To collect logs through REST API, follow the below steps:

- After logging in to GreyNoise, navigate to your [account page](https://viz.greynoise.io/account/api-key).
- Click on "View API Key" to display and copy your unique API key.

### Enabling the integration in Elastic:

1. In Kibana, go to **Management > Integrations**.
2. In the "Search for integrations" search bar, type **GreyNoise**.
3. Click on the **GreyNoise** integration from the search results.
4. Click on the **Add GreyNoise** button to add the integration.
5. While adding the integration, to collect logs via REST API, provide the following details:
   - Access Token
   - Interval
   - (Optional) Query to add custom query filtering.
6. Click on **Save and Continue** to save the integration.
**Note:** Please make sure the "last_seen" field should not be included in the query, as it is predefined with a fixed value of "1d".

## Transforming Data for Up-to-Date Insights

To keep the collected data up to date, **Transforms** are used.

Users can view the transforms by navigating to **Management > Stack Management > Transforms**.

Here, users can see continuously running transforms and also view the latest transformed GreyNoise data in the **Discover** section.

The `labels.is_transform_source` field indicates log origin:
- **False** for transformed index
- **True** for source index

Currently, one transform is running for IP datastream:

| Transform Name                                                                        | Description                                              |
| ------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| IP Transform (ID: `logs-ti_greynoise.ip`)                        | Keeps IP entity type data up to date.                    |

For example:

- The query `event.module: ti_greynoise and labels.is_transform_source: true` indicates that the logs originate from the **source index**.
- The query `event.module: ti_greynoise and labels.is_transform_source: false` indicates that the logs originate from the **transformed index**.

A **retention policy** is used to remove data older than the default retention period. For more details, refer to the [Retention Policy Documentation](<https://www.elastic.co/guide/en/elasticsearch/reference/current/put-transform.html#:~:text=to%20false.-,retention_policy,-(Optional%2C%20object)%20Defines>).

In this integration, IP data stream has a **retention period of 7 days**.

### Enrichment with Detection Rules

Detection Rules match the user's Elastic environment data with GreyNoise data, generating an alert if a match is found. To access detection rules:

1. Navigate to **Security > Rules > Detection Rules** and click on **Add Elastic Rules**.
2. Search for **GreyNoise** to find prebuilt Elastic detection rule.
3. One detection rule is available for **IP**. Users can install and enable rule as needed.

To tailor a rule based on Elastic environment:

1. Click the three dots on the right side of any detection rule.
2. Select **Duplicate Rule**.
3. Modify the duplicated rule to tailor it to your Elastic environment:
   - **Index Pattern**: Add the index pattern relevant to your data. Keeping this specific ensures optimal performance.
   - **Custom Query**: Further refine rule conditions.
   - **Indicator Mapping**: Map relevant fields from your Elastic environment to GreyNoise fields. Do not modify the **indicator index field**.
   - **Schedule Rules**:
     - **Set Runs Every** - Defines how frequently the rule runs.
     - **Additional Lookback Time** - Specifies how far back to check for matches.

Once saved, successfully executed rules will generate alerts. Users can view these alerts in the **Alerts** section.

**Note:** One transform runs in the background to filter relevant data from alerts. The `data_stream.dataset: ti_greynoise.enriched_ioc` field represents logs for enriched threat intelligence data, which can be analyzed in the **Discover** section.

The following is the name of the one sample rule:

| Sample Rule Name                                             | Description                                                                                                                           |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| GreyNoise IP Address IOC Correlation        | Detects and alerts on matches between IP Address IOCs collected by GreyNoise data with user's selected Elastic environment data.            |

1. If an event contains multiple matching mappings (e.g., two IP fields within the same event match GreyNoise data), only one alert per detection rule will be generated for that event.
2. If an IOC from the user's Elasticsearch index is enriched with GreyNoise information, and the GreyNoise information is updated later, the changes are not reflected in the dashboards because Elastic detection rules only run on live data.

## Troubleshooting

1. If any latency issues occur during data collection, consider increasing the `HTTP Client Timeout` configuration parameter.
2. If any server-side errors occur, consider reducing the `Page Size` configuration parameter.
   **Note:** Please avoid setting the `Page Size` too low, as this may increase the number of API requests, potentially leading to processing issues.
3. If events are not appearing in the transformed index, check if transforms are running without errors. If you encounter issues, refer to [Troubleshooting transforms](https://www.elastic.co/guide/en/elasticsearch/reference/current/transform-troubleshooting.html).
4. If detection rules take longer to run, ensure you have specified index patterns and applied queries to make your source events more specific.
   **Note:** More events in index patterns means more time needed for detection rules to run.
5. Ensure that relevant fields are correctly mapped in the **Indicator Mapping** section. Verify that fields in the specified index pattern are properly mapped, and ensure entity-specific fields (e.g., IP fields to IP fields) are accurately configured.

## Logs Reference

### IP

This is the `IP` dataset. It uses [GNQL Endpoint](https://docs.greynoise.io/reference/gnqlquery-1) to fetch data from GreyNoise with "last_seen:1d". It uses version v3 of the API to collect indicators. Currently [Triage](https://docs.greynoise.io/docs/intelligence-module-triage) and [Business Services](https://docs.greynoise.io/docs/intelligence-module-business-services) Intelligence Modules are being collected through this data stream.

#### Example

{{event "ip"}}

{{fields "ip"}}
