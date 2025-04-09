# Google Threat Intelligence

## Overview

[Google Threat Intelligence](https://gtidocs.virustotal.com/) is a security solution that helps organizations detect, analyze, and mitigate threats. It leverages Google's global telemetry, advanced analytics, and vast infrastructure to provide actionable insights. Key features include threat detection, malware and phishing analysis, and real-time threat alerts.

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

- VirusTotal URL will work as the base URL for this integration: https://www.virustotal.com
- An API key will be used to authenticate your request.
- **Time Selection of Initial Interval and Interval**:
  - Users need to specify the **initial interval** and **interval** in an hourly format, such as **2h, 3h**, etc.
**Note:** Please make sure both initial interval and interval are in hours and greater than 1 hour.

### Enabling the integration in Elastic:

1. In Kibana, go to **Management > Integrations**.
2. In the "Search for integrations" search bar, type **Google Threat Intelligence**.
3. Click on the **Google Threat Intelligence** integration from the search results.
4. Click on the **Add Google Threat Intelligence** button to add the integration.
5. While adding the integration, to collect logs via REST API, provide the following details:
   - Enable the type of data stream you have access to.
   - Access Token
   - Initial Interval
   - Interval
   - (Optional) Query to add custom query filtering on relationship, GTI score, and positives.
6. Click on **Save and Continue** to save the integration.

## Transforming Data for Up-to-Date Insights

To keep the collected data up to date, **Transforms** are used.

Users can view the transforms by navigating to **Management > Stack Management > Transforms**.

Here, users can see continuously running transforms and also view the latest transformed GTI data in the **Discover** section.

The `labels.is_transform_source` field indicates log origin:
- **False** for transformed index
- **True** for source index

Currently, four transforms are running across all 15 data streams:

| Transform Name                                                                        | Description                                              |
| ------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| IP IOC Stream Transform  (ID: `logs-ti_google_threat_intelligence.ip_ioc_st`)         | Keeps IP entity type data up to date for IOC Stream.     |
| URL IOC Stream Transform  (ID: `logs-ti_google_threat_intelligence.url_ioc_st`)       | Keeps URL entity type data up to date for IOC Stream.    |
| Domain IOC Stream Transform  (ID: `logs-ti_google_threat_intelligence.domain_ioc_st`) | Keeps Domain entity type data up to date for IOC Stream. |
| File IOC Stream Transform  (ID: `logs-ti_google_threat_intelligence.file_ioc_st`)     | Keeps File entity type data up to date for IOC Stream.   |

For example:

- The query `event.module: ti_google_threat_intelligence and labels.is_transform_source: true` indicates that the logs originate from the **source index**.
- The query `event.module: ti_google_threat_intelligence and labels.is_transform_source: false` indicates that the logs originate from the **transformed index**.

A **retention policy** is used to remove data older than the default retention period. For more details, refer to the [Retention Policy Documentation](<https://www.elastic.co/guide/en/elasticsearch/reference/current/put-transform.html#:~:text=to%20false.-,retention_policy,-(Optional%2C%20object)%20Defines>).

In this integration, all data streams have a **retention period of 30 days**.

### Enrichment with Detection Rules

Detection Rules match the user's Elastic environment data with GTI data, generating an alert if a match is found. To access detection rules:

1. Navigate to **Security > Rules > Detection Rules** and click on **Add Elastic Rules**.
2. Search for **Google Threat Intelligence** to find prebuilt Elastic detection rules.
3. Four detection rules are available for **IP, URL, File, and Domain**. Users can install one or more rules as needed.

To tailor a rule based on elastic Environment:

1. Click the three dots on the right side of any detection rule.
2. Select **Duplicate Rule**.
3. Modify the duplicated rule to tailor it to your Elastic environment:
   - **Index Pattern**: Add the index pattern relevant to your data. Keeping this specific ensures optimal performance.
   - **Custom Query**: Further refine rule conditions.
   - **Indicator Mapping**: Map relevant fields from your Elastic environment to GTI fields. Do not modify the **indicator index field**.
   - **Schedule Rules**:
     - **Set Runs Every** - Defines how frequently the rule runs.
     - **Additional Lookback Time** - Specifies how far back to check for matches.

Once saved, successfully executed rules will generate alerts. Users can view these alerts in the **Alerts** section.

**Note:** One transforms run in the background to filter relevant data from alerts. The  `data_stream.dataset: ti_google_threat_intelligence.enriched_ioc_stream` field represents logs for enriched threat intelligence data, which can be analyzed in the **Discover** section.

The following are the names of the four sample rules:

| Sample Rule Name                                             | Description                                                                                                                           |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| Google Threat Intelligence URL IOC Stream Correlation        | Detects and alerts on matches between URL IOCs collected by GTI IOC Stream data with user's selected Elastic environment data.        |
| Google Threat Intelligence Domain IOC Stream Correlation     | Detects and alerts on matches between Domain IOCs collected by GTI IOC Stream data with user's selected Elastic environment data.     |
| Google Threat Intelligence File IOC Stream Correlation       | Detects and alerts on matches between File IOCs collected by GTI IOC Stream data with user's selected Elastic environment data.       |
| Google Threat Intelligence IP Address IOC Stream Correlation | Detects and alerts on matches between IP Address IOCs collected by GTI IOC Stream data with user's selected Elastic environment data. |

## Limitations

1. If an event contains multiple matching mappings (e.g., two file hash fields within the same event match GTI data), only one alert per detection rule will be generated for that event.
2. If an IOC from the user's Elasticsearch index is enriched with GTI information, and the GTI information is updated later, the changes are not reflected in the dashboards because Elastic detection rules only run on live data.

## Troubleshooting

1. If you see an error like `Package 2025031310 is not available until 2025-03-13 at 11:00 UTC because of privacy policy.`, ensure that your initial interval and interval are set in hours and are greater than one hour.
2. If events are not appearing in the transformed index, check if transforms are running without errors. If you encounter issues, refer to [Troubleshooting transforms](https://www.elastic.co/guide/en/elasticsearch/reference/current/transform-troubleshooting.html).
3. If detection rules take longer to run, ensure you have specified index patterns and applied queries to make your source events more specific.
   **Note:** More events in index patterns mean more time needed for detection rules to run.
4. Ensure that relevant fields are correctly mapped in the **Indicator Mapping** section. Verify that fields in the specified index pattern are properly mapped, and ensure entity-specific fields (e.g., IP fields to IP fields, keyword fields like file hash SHA256 to corresponding file hash SHA256 fields) are accurately configured.

## Logs Reference

### IOC Stream

This is the `IOC Stream` dataset.

#### Example

{{event "ioc_stream"}}

{{fields "ioc_stream"}}
