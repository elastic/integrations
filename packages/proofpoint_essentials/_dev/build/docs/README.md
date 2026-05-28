# Proofpoint Essentials Integration for Elastic

## Overview
The Proofpoint Essentials integration with Elastic enables the collection of threats for monitoring and analysis. This valuable data can be leveraged within Elastic to analyze potential threat signals, including spam, phishing, business email compromise (BEC), imposter emails, ransomware, and malware.

This integration utilizes the [Proofpoint Essentials Threat API](https://help.proofpoint.com/Essentials/Additional_Resources/API_Documentation/Essentials_Threat_API) to collect threat events.

### Compatibility

The Proofpoint Essentials integration uses the REST API. It uses the `/v2/siem/all` to collect threat events.

### How it works

The **threat** data stream uses the `/v2/siem/all` endpoint to gather all threats starting from the configured initial interval. Subsequently, it fetches the recent threats available at each specified interval.

The gathered threat data is subsequently routed into individual data streams, each corresponding to a specific threat type.

## What data does this integration collect?

The Proofpoint Essentials integration collects threat events of the following types:

- `clicks_blocked`: events for clicks on malicious URLs blocked by URL Defense.
- `clicks_permitted`: events for clicks on malicious URLs permitted by URL Defense.
- `message_blocked`: events for blocked messages that contain threats recognized by URL Defense or Attachment Defense.
- `message_delivered`: events for delivered messages that contain threats recognized by URL Defense or Attachment Defense.

### Supported use cases
Integrating Proofpoint Essentials with Elastic SIEM enriches your security operations with targeted email threat intelligence. It enables the detection, investigation, and analysis of phishing, malware, and other email-based threats by leveraging detailed data on clicks and message events.

## What do I need to use this integration?

### From Proofpoint Essentials

#### Collecting data from Essentials Threat API

1. Navigate to 
  - Go to **Account Management > Integrations**, then select the **Integration Keys** tab.
2. Add a New Key
  - Click **Add Integration Key** in the upper right-hand corner.
3. Enter Key Details
  - Provide a **description** to help identify the purpose of the key.
  - In the **Access Type** dropdown, select **SIEM Threat Events**
4. Set Scope
  - If you are part of an **organisation**, the **Scope** field will be locked to **My Organisation Only**.
  - If you are a **partner**, you can choose between:
    - **My Organisation Only**
    - **My Organisation and All Child Organisations**
5. Create and Save Credentials
  - After clicking **Create**, you’ll receive **API Key** and **API Key Secret**.
6. Activation Time
  - The key may take up to **30 minutes** to become active.

For more details, check [Documentation](https://help.proofpoint.com/Essentials/Product_Documentation/Account_Management/Integrations/Integration_Keys).

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Agentless deployment

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. Agentless deployments provide a means to ingest data while avoiding the orchestration, management, and maintenance needs associated with standard ingest infrastructure. Using an agentless deployment makes manual agent deployment unnecessary, allowing you to focus on your data instead of the agent that collects it.

For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html) 

### Onboard / configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Proofpoint Essentials**.
3. Select the **Proofpoint Essentials** integration from the search results.
4. Select **Add Proofpoint Essentials** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect Proofpoint Essentials logs via API**, you'll need to:

        - Configure **URL**, **API Key**, and **API Key Secret**.
        - Adjust the integration configuration parameters if required, including the Interval, Collect Customer Data, Collect Own Data, Preserve original event etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Proofpoint Essentials**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

#### Clicks Blocked

{{fields "clicks_blocked"}}

#### Clicks Permitted

{{fields "clicks_permitted"}}

#### Messages Blocked

{{fields "message_blocked"}}

#### Messages Delivered

{{fields "message_delivered"}}

### Inputs used

These inputs are used in this integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration uses the following APIs:

- [Proofpoint Essentials Threat API](https://help.proofpoint.com/Essentials/Additional_Resources/API_Documentation/Essentials_Threat_API).
