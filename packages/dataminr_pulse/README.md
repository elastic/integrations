# Dataminr Pulse Integration User Guide

# Overview

### From Alerts to Action—Dataminr Pulse for Elastic Security

Embed Dataminr Pulse real-time, actionable intelligence directly into Elastic Security. Transform the earliest external threat signals from over 1.1 million public, deep, and dark web sources into Elastic-native detections, enriched indices, and automated workflows.

The Dataminr Pulse integration for Elastic Security seamlessly bridges the gap between external real-time data and your internal security operations. By leveraging the Elastic Agent with a CEL (Common Expression Language) input, the integration polls the Dataminr Pulse v4 API at configurable intervals—automatically managing OAuth token refresh and cursor-based pagination to ensure a continuous, resilient data flow.

### Turn Signal Overload into Real-Time, AI-Powered Intelligence

Stay ahead of the threat curve and be the first to see rapidly emerging and evolving threats, vulnerabilities, exploits, ransomware activity, third-party incidents, and more—often hours or days before traditional sources.

**Unmatched Coverage, Precision, and Granularity**

With Dataminr Pulse for Cyber Risk, security teams gain a critical time advantage. Dataminr processes more than 45 terabytes of daily public data, leveraging over 55 proprietary LLMs and 15 years of historic alerting information. With multimodal fusion AI, GenAI, and Agentic AI deeply embedded into the platform, security teams can:

* **Dynamically detect and defend** digital assets beyond the perimeter.
* **Unearth hidden threats** and close blind spots with advanced processing of text, images, video, and machine signals.
* **Leverage Agentic AI-powered Intel Agents** to autonomously assemble adversary context, including TTPs, IOCs, CVEs, and MITRE ATT\&CK® mappings.
* **Proactively prioritize and patch** fast-breaking vulnerabilities and exploits.


**Accelerate Elastic Workflows with Actionable Context**

* **Native ECS Mapping:** Ingested alerts are automatically mapped to the Elastic Common Schema (ECS) and stored in the logs-dataminr\_pulse.alerts-\* data stream for immediate correlation.
* **Granular Entity Expansion:** The integration automatically expands alerts containing multiple discovered entities, such as vulnerabilities, threat actors, malware, IP addresses, and URLs into individual documents for deep, granular analysis.
* **Integrated Detection & Response:** Populate Elastic Security signals and enrich indices to power advanced hunting, Kibana Dashboards, and Elastic Defend workflows.


**Address Your Critical Use Cases with Dataminr**

| Use Case | How Dataminr & Elastic Work Together |
| :---- | :---- |
| **Cyber Threat Intelligence**  | Piece together attack context with crucial details about threat actors and malware directly within the Elastic Security Threat Intel view and custom dashboards specific to your Dataminr topics. |
| **Vulnerability Prioritization** | See the earliest signals of PoC exploitation to prioritize patching within the Elastic Vulnerability Management framework. |
| **Third-Party Risk** | Instantly identify and track supply chain attacks and vendor disruptions as they unfold in real-time. |
| **Digital Risk Protection** | Spot credential dumps, phishing attempts, and brand impersonations involving your digital footprint. |
| **Cyber-Physical Convergence** | Assess the complete blast radius of physical events and coordinate a unified response to converged threats. |

# Dependencies

Before installing, ensure the following requirements are met.

## Dataminr Dependencies

| Dependency | Requirement |
| :---- | :---- |
| Active Dataminr Pulse API account | Required |
| Client ID | Required |
| Client Secret | Required |
| Dataminr Pulse API version | v4 |

## Elastic Security Dependencies

| Dependency | Requirement |
| :---- | :---- |
| Elastic Stack version | 8.13.0 or newer |
| Kibana version | 8.13.0 or newer |
| Elastic Agent version | 8.13.0 or newer |
| Elastic subscription | Basic or higher |

## Network Requirements

The host running the Elastic Agent must have outbound HTTPS (port 443\) access to the following endpoints:

| Destination | Purpose |
| :---- | :---- |
| userauth.dataminr.com | For OAuth authentication |
| api.dataminr.com | For fetching alerts from Pulse API |
| Fleet Server URL | Agent enrollment and policy management within the clients systems |

**Note:** No inbound ports are required on the agent host.

# Set up

## Install the Integration

1. Log in to elastic and navigate to the **Integrations** page under **Data Management**.
2. Search for **Dataminr Pulse** in the integrations catalog.
3. Click the **Dataminr Pulse** integration card, then click **Add Dataminr Pulse**.

## Configure the Integration

#### Dataminr Configuration

To use this integration, you need a Dataminr Pulse API account with a valid Client ID and Client Secret. Contact your Dataminr account representative to obtain the API credentials.

**Important:** Keep your Client Secret secure. It will be stored as a secret value in the Elastic Agent policy and will not be visible after saving.

#### Elastic Configuration

#### **Step 1: Configure and Deploy the Integration**

After clicking **Add Dataminr Pulse** from the integrations page, fill in the configuration form.

1. Browse to the data management and select integrations.
2. Search ‘Dataminr Pulse’ to install the integration and follow the onscreen instructions.
3. Optionally, configure the **Polling Interval**, and **Page Size**. The defaults work for most deployments.
4. Select an existing **Agent policy** or create a new one.
5. Click **Save and continue**, then **Save and deploy changes**.

#### **Configuration Parameters**

The table below describes all available configuration parameters.

| Parameter | Description | Required | Default |
| :---- | :---- | :---- | :---- |
| Integration name | A descriptive name visible on the Elastic Agent policy. | No | dataminr\_pulse |
| API URL | The full URL for the Dataminr Pulse alerts endpoint. | Yes | https://api.dataminr.com/pulse/v1/alerts |
| Client ID | Your Dataminr API Client ID for OAuth token generation. | Yes | \- |
| Client Secret | Your Dataminr API Client Secret for OAuth token generation. Stored securely. | Yes | \- |
| Interval | How often the integration polls the Dataminr API for new alerts (e.g., 5m, 1m, 10m). | Yes | 5m |
| Page Size | Maximum number of alerts returned per API request. The maximum allowed value is 100\. | Yes | 40 |
| Tags | Custom tags applied to each ingested event. | No | forwarded, dataminr-pulse-alerts |
| Preserve original event | When enabled, stores the raw API response in the event.original field. Useful for debugging. | No | false |
| Enable request tracing | Logs full HTTP request/response details for debugging. Do not enable in production \- this logs credentials in plain text. | No | false |
| Processors | Custom Elastic Agent processors in YAML format, applied before data is sent to Elasticsearch. | No | \- |

#### **Configuration Performance Recommendations**

* **Polling Interval**: Start with the default of 5m. Reduce to 1m only if you need near-real-time alert ingestion and your Dataminr API quota allows it.
* **Page Size**: The default of 40 works well for most deployments. Increase up to 100 if you expect high alert volumes to reduce the number of API calls.
* **Preserve original event**: Keep disabled in production. Enabling it roughly doubles the storage per document.

#### **Step 2: Validate the Data Flow**

After deploying the integration, verify that data is flowing correctly.

##### **Fleet**

1. Navigate to **Assets** \> **Fleet**.
2. Under **Agents** locate your enrolled agent.
3. Verify the agent status is **Healthy** (green).
4. Click the agent name, then click the **Logs** tab.
5. Look for log entries showing successful execution of CEL script within agent (Ex: “Unit state changed cel-default (STARTING-\>HEALTHY): Healthy”)

##### **Discover**

1. Navigate to **Discover** and create a session
2. Set the **Index pattern** to logs-dataminr\_pulse.alerts\* under **Data view**
3. Select the time to be the last hour, and confirm documents are appearing.

##### **Index Management**

1. Navigate to **Data Management** \> **Streams**
2. Search for logs-dataminr\_pulse.alerts\*. Verify the index exists and the document count is increasing.

##### **Dashboards**

1. Navigate to **Dashboards**.
2. Search for **Dataminr**. The integration includes pre-built dashboards for alert monitoring.
3. Open a dashboard and verify it displays data.

## Delete the Integration

To remove the Dataminr Pulse integration from an agent policy:

1. Navigate to **Assets** \> **Fleet \> Policies**
2. Click the policy that contains the Dataminr Pulse integration.
3. Locate the **Dataminr Pulse** integration entry and click the **Actions** menu (three dots), then select **Delete integration**.

**Note:** Deleting the integration from the policy stops data collection but does not remove already-ingested data.

## Reset Integration Assets

If integration assets (dashboards, index templates, ingest pipelines) become corrupted or out of sync, you can reset them.

1. Navigate to **Data Management** \> **Integrations**.
2. Click **Dataminr Pulse**.
3. Select the **Settings** tab.
4. Click **Reinstall Dataminr Pulse**. This reinstalls dashboards, index templates, and ingest pipelines to their default state.

# Data Mappings

The integration maps Dataminr Pulse alert fields to Elastic Common Schema (ECS) fields. Custom fields are stored under the dataminr\_pulse namespace for reference.

## ECS Field Mappings

| Dataminr Pulse Field                  | ECS Field                                     | Description                                                        |
|:--------------------------------------|:----------------------------------------------|:-------------------------------------------------------------------|
| Alert timestamp                       | @timestamp                                    | Event timestamp                                                    |
| Alert headline                        | message                                       | Single-sentence event summary                                      |
| Alert ID                              | event.id                                      | Unique alert identifier                                            |
| Alert creation time                   | event.created                                 | When the alert was created                                         |
| Alert priority (Alert, Urgent, Flash) | event.severity                                | Numeric severity (10, 20, 30\)                                     |
| Dataminr alert URL                    | event.url                                     | Link to alert in Dataminr platform                                 |
| Dataminr alert location coordinates   | source.geo.location                           | Coordinates of the Dataminr alert                                  |
| Dataminr alert location name          | geo.name                                      | address of the Dataminr alert                                      |
| Dataminr entity category              | event.category                                | Categories \- Threat Actor, Vulnerability, Malware                 |
| Threat actor name                     | threat.group.name                             | Threat actor name (MITRE ATT\&CK)                                  |
| Threat actor aliases                  | threat.group.alias                            | Threat actor alternative names                                     |
| Threat actor country of origin        | threat.indicator.geo.country\_iso\_code       | Country of Origin for threat actors                                |
| CVE ID                                | vulnerability.id                              | CVE identifier                                                     |
| CVSS score                            | vulnerability.score.base                      | CVSS base score                                                    |
| Vulnerability description             | vulnerability.description                     | Summary of the vulnerability                                       |
| Type to distinguish URL vs IP IOC     | threat.enrichments\[\].indicator.type         | Values \- ip4-ddr, ip6-addr, url                                   |
| URL                                   | Threat.enrichments\[\].indicator.url.original | URL discovered to be related to the alert, as in the original form |
| URL or IP addresses                   | threat.enrichments\[\].indicator.name         | URL/IP addresses discovered to be related to the alert.            |
| IP Addresses                          | threat.enrichments\[\].indicator.ip           | IP Addresses discovered to be related to the alert.                |
| Port                                  | threat.enrichments\[\].indicator.port\[\]     | Ports discovered to be associated with the IP addresses above      |

## Custom Dataminr Fields

| Field | Type | Description |
| :---- | :---- | :---- |
| dataminr\_pulse.categories.name | keyword | Alert topic categories |
| dataminr\_pulse.companies.name | keyword | Affected company names |
| dataminr\_pulse.sectors.name | keyword | Industry sectors |
| dataminr\_pulse.source.href | keyword | URL to the public source post |
| dataminr\_pulse.source.channels | keyword | Source channels (e.g., sensor) |
| dataminr\_pulse.source.media.href | keyword | Media attachment URLs |
| dataminr\_pulse.intel\_agents.summary | keyword | AI-generated critical context summary |
| dataminr\_pulse.watchlists\_matched\_by\_type.name | keyword | Matched watchlist names |
| dataminr\_pulse.alert\_type.name | keyword | Alert priority level (Alert, Urgent, Flash) |
| dataminr\_pulse.live\_brief.summary | keyword | AI-generated event summary |
| dataminr\_pulse.live\_brief.version | keyword | Live Brief version |
| dataminr\_pulse.live\_brief.timestamp | date | Live Brief generation timestamp |
| Dataminr\_pulse.threatactor | keyword | Threat actors discovered in the alert |
| Dataminr\_pulse.threatactor.alias | keyword | Alternative names of threat actors discovered in the alert |
| dataminr\_pulse.threatactor.country\_of\_origin | keyword | Country of origin for threat actors discovered in the alert |
| dataminr\_pulse.vulnerability.name | keyword | Vulnerability identifiers (CVE IDs) |
| Dataminr\_pulse.event.malware | keyword | Malwares discovered in the alert |
| dataminr\_pulse.platforms | keyword | Operating systems that were discovered to be impacted because of the malwares |
| Dataminr\_pulse.url | keyword | URLs discovered to be impacted |
| Dataminr\_pulse.ip | keyword | IP address (for IP-type entities) |

## Operational Fields

| Field | Type | Description |
| :---- | :---- | :---- |
| dataminr\_pulse.log.log\_type | keyword | Values: “alert-fetch” or “auth” |
| dataminr\_pulse.log.api\_endpoint | keyword | Full API used to fetch alerts or for authentication |
| dataminr\_pulse.log.http\_status\_code | keyword | HTTP response for the API call |
| dataminr\_pulse.log.fetched\_alerts | long | Number of alerts fetched in the batch |
| dataminr\_pulse.log.fetch\_timestamp | date | Timestamp when the Alert API call was made |
| dataminr\_pulse.log.next\_cursor | keyword | Pagination cursor to be used in next batch |
| dataminr\_pulse.log.status | keyword | If the iteration failed or succeded |

# Troubleshooting

## Enable Request Tracing

Request tracing logs full HTTP request and response details, which is useful for diagnosing connectivity or authentication issues.

**Important:** Request tracing logs credentials in plain text. Only enable it temporarily for debugging and disable it immediately after.

1. Navigate to **Assets** \> **Fleet \> Policies**
2. Click the policy that contains the Dataminr Pulse integration.
3. Locate the **Dataminr Pulse** integration entry and click the **Actions** menu (three dots), then select **Edit integration**.
4. Under advanced settings, set **Enable request tracing** to true.
5. Click **Save and deploy changes**.
6. To view traces, navigate to **Assets** \> **Fleet** \> **Agents**
7. Click the agent, then click **Actions** \> **Request diagnostics**.
8. Download the diagnostics bundle and examine the HTTP trace logs in the agent log files.

### Common Errors

| HTTP Status | Error | Explanation |
| :---- | :---- | :---- |
| 400 | Bad Request | The API URL is malformed or a request parameter is invalid. Verify the API URL and Base URL fields. |
| 401 | Unauthorized | Authentication failed. Verify your Client ID and Client Secret are correct and the account is active. |
| 403 | Forbidden | The API credentials do not have permission to access the requested resource. Contact your Dataminr account representative. |
| 404 | Not Found | The API endpoint URL is incorrect. Ensure the API URL is set to https://api.dataminr.com/pulse/v1/alerts. |
| 429 | Too Many Requests | API rate limit exceeded. Increase the Interval value or reduce the Page Size. |

### No Data Appearing

1. Check Agent Status: Navigate to Fleet \> Agents and verify the agent is Healthy.
2. Check Agent Logs: Click the agent and review the Logs tab for error messages.
3. Test Credentials: On the agent host, run:
    1. curl \-X POST [https://userauth.dataminr.com/auth/2/token](https://userauth.dataminr.com/auth/2/token)  \-H "Content-Type: application/x-www-form-urlencoded"  \-d "grant\_type=api\_key\&client\_id=YOUR\_ID\&client\_secret=YOUR\_SECRET"
    2. A successful response returns a JSON object with dmaToken and expire fields.
4. Check Data Stream: In Dev Tools, run:
    1. GET logs-dataminr\_pulse.alerts-\*/\_count
    2. If the count is 0, the integration is not receiving data from the API. Review the agent logs for details.

### Duplicate Alerts

The integration uses document fingerprinting to prevent duplicates. If you observe duplicate documents:

1. Verify the ingest pipeline is installed by running in Dev Tools:
    1. GET \_ingest/pipeline/logs-dataminr\_pulse.alerts-\*
    2. If missing, reset integration assets (see **Reset Integration Assets**).