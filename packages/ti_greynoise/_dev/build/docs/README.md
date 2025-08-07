# GreyNoise

## Overview

[GreyNoise](https://www.greynoise.io/) is a cybersecurity platform that helps security teams filter out "internet noise" — background internet scanning activity that's not necessarily targeted or malicious. It collects, analyzes, and labels massive amounts of data from internet-wide scans, typically originating from bots, security researchers, or compromised systems.

## Prerequisites for GreyNoise

Customers must have access to the **Enterprise API** to fetch data from GreyNoise. You can verify your API key access [here](https://viz.greynoise.io/account/api-key).

## Requirements

### Agentless-enabled integration
Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation
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

## Enrichment with Detection Rules

Detection Rules match your Elastic environment data with GreyNoise data, generating an alert when a match is found.

Follow **Steps to Create Detection Rule** below to create indicator match detection rule in Elastic.

### Steps to Create Detection Rule

1. Navigate to **Security > Rules > Detection Rules** and click **Create New Rule**.
2. Select **Indicator Match** as the rule type and do following changes.
3. In **Define Rule** section:
    - **Index Pattern**: Add the index pattern relevant to your data. Keeping this specific ensures optimal performance.
    - **Custom Query**: Must include `NOT event.module : "ti_greynoise"` to exclude GreyNoise events.
    - **Indicator index patterns**: Use `logs-ti_greynoise_latest.ip*`.
    - **Indicator index query**: Refine indcator index with something like `@timestamp >= "now-7d/d"`.
    - **Indicator Mapping**:
        - **Field**: Map to the field in your Elastic environment containing IPs.
        - **Indicator Index Field**: threat.indicator.ip
    - **Required fields (Optional)**: Add `threat.indicator.ip`.
    - **Related integrations (Optional)**: Add `GreyNoise`.
4. In **About Rule** section:
    - **Name**: e.g `GreyNoise IP IOC Correlation`.
    - **Description**: e.g `This rule is triggered when IP Address IOC's collected from the GreyNoise Integration have a match against IP Address that were found in the customer environment.`.
    - **Default Severity**: e.g `critical`.
    - **Tags**: Add `GreyNoise` (used for filter Alerts generated by this rule by rule transforms).
    - **Max alerts per run**: Default is 100; configurable up to 1000.
    - **Indicator prefix override**: Set to `greynoise.ip` to enrich alerts with GreyNoise data.
5. In **Schedule Rules** section:
    - **Set Runs Every** - Defines how frequently the rule runs.
    - **Additional Lookback Time** - Specifies how far back to check for matches.

Once the rule is saved and enabled, alerts will appear in the **Security > Alerts** section when matches are detected.

The following transform and its associated pipelines are used to filter relevant data from alerts. Follow **Steps to enable rule transforms** to enable these transforms and populate `Threat Intelligence` dashboard.

| Transform Name                                                                                                                                          | Description                                                                     |
| ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| Detected IOC Transform  (ID: `logs-ti_greynoise.rule`, Pipeline: `ti_greynoise-correlation_detection_rule-pipeline`)  | Filters and extracts necessary information from Detected IOCs. |

### Steps to enable rule transforms

1. Navigate to **Stack Management > Transforms** in Kibana.
2. Locate the transform you want to enable by searching for its **Transform ID**.
3. Click the **three dots** next to the transform, then select **Edit**.
4. Under the **Destination configuration** section, set the **Ingest Pipeline**:
   - Rule transform in the **GreyNoise** integration has a corresponding ingest pipeline.
   - Refer to the **Transforms table** above for the appropriate pipeline name associated with transform.
   - Prefix the pipeline name with the integration version.
     For example:
     ```
     {package_version}-ti_greynoise-correlation_detection_rule-pipeline
     ```
   - Click **Update** to save the changes.
5. Click the **three dots** again next to the transform and select **Start** to activate it.

**Note:** After updating the integration, make sure to update the pipeline prefix accordingly.

## Troubleshooting

1. If you experience latency issues during data collection, consider increasing the `HTTP Client Timeout` configuration parameter.
2. If server-side errors occur, consider reducing the `Page Size` configuration parameter.
   **Note:** Avoid setting the `Page Size` too low, as this may increase the number of API requests, potentially causing processing issues.
3. If events are not appearing in the transformed index, check if transforms are running without errors. For issues, refer to [Troubleshooting transforms](https://www.elastic.co/guide/en/elasticsearch/reference/current/transform-troubleshooting.html).
4. If detection rules take longer to run, ensure you have specified index patterns and applied queries to make your source events more specific.
   **Note:** More events in index patterns means more time needed for detection rules to run.
5. Ensure that relevant fields are correctly mapped in the **Indicator Mapping** section. Verify that fields in the specified index pattern are properly mapped, and ensure entity-specific fields (e.g., IP fields to IP fields) are accurately configured.
6. If any transform is not in a **Healthy** state, try resetting it:
   - Click the **three dots** next to the transform, then select **Reset**.
   - After resetting, restart the transform.

## Logs Reference

### IP

This is the `IP` dataset. It uses the [GNQL Endpoint](https://docs.greynoise.io/reference/gnqlquery-1) to fetch data from GreyNoise with "last_seen:1d". It uses version v3 of the API to collect indicators. Currently, the [Triage](https://docs.greynoise.io/docs/intelligence-module-triage) and [Business Services](https://docs.greynoise.io/docs/intelligence-module-business-services) Intelligence Modules are being collected through this data stream.

#### Example

{{event "ip"}}

{{fields "ip"}}
