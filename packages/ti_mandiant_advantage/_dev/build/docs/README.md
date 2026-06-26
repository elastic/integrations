# Mandiant Advantage

## Overview

The [Mandiant Advantage](https://www.mandiant.com/advantage) integration allows users to retrieve IOCs (Indicators of Compromise) from the Threat Intelligence Advantage Module. 

These indicators can be used for correlation in Elastic Security to help discover potential threats. Mandiant Threat Intelligence gives security practitioners unparalleled visibility and expertise into threats that matter to their business right now.

Our threat intelligence is compiled by over 500 threat intelligence analysts across 30 countries, researching actors via undercover adversarial pursuits, incident forensics, malicious infrastructure reconstructions and actor identification processes that comprise the deep knowledge embedded in the Mandiant Intel Grid.

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Data streams

The Mandiant Advantage integration collects one type of data stream: `threat_intelligence`

### **Threat Intelligence**

IOCs are retrieved via the Mandiant Threat Intelligence API.


## Compatibility

- This integration has been tested against the Threat Intelligence API v4.


## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/starting-with-the-elasticsearch-platform-and-its-solutions/current/getting-started-observability.html) guide.

For instructions on how to get Threat Intelligence API v4 credentials, see the [Mandiant Documentation Portal.](https://docs.mandiant.com/home/mati-threat-intelligence-api-v4#tag/Getting-Started)

### Filtering IOCs

The integration allows you to filter the amount of IOCs that are ingested, by using the following configuration parameters:

* **Initial interval**
  * The time in the past to start the collection of Indicator data from, based on an indicators last_update date. 
  * Supported units for this parameter are h/m/s. The default value is 720h (i.e 30 days)
  * You may reduce this interval if you do not want as much historical data to be ingested when the integration first runs.
* **Minimum IC-Score**
  * Indicators that have an IC-Score greater than or equal to the given value will be collected. 
  * Indicators with any IC-Score will be collected if a value is set to 0.
  * You might set this to a different value such as 80, to ensure that only high confidence indicators are ingested.  

## Logs reference

### Threat Intelligence

Retrieves IOCs using the Mandiant Threat Intelligence API over time.

{{event "threat_intelligence"}}

{{fields "threat_intelligence"}}
