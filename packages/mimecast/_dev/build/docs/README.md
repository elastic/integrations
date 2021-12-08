# Mimecast Integration

The Mimecast integration collects events from the Mimecast API.

Full guide how to configure, deploy and use this integration find [here]()

# Documenation

## Introduction

The purpose of this integration is to fetch logs from the Mimecast API periodically and ingest them into the Elastic in automated manner.

The integration is made based on the specification defined by the Elastic team. Each Elastic Integration is an Elastic Package that defines how to observe a specific product with the Elastic Stack.

An Elastic Package may define configuration for the Elastic Agent as well as assets for the Elastic Stack (such as Kibana dashboards and Elasticsearch index templates). It should also include documentation about the package. Finally, a package may also define tests to ensure that it is functioning as expected.
Elastic Packages have a certain, well-defined structure. This structure is described by the Package Specification. The repository is also used for discussions about extending the specification (with proposals).

More about Elastic package stack and general idea about making integration this way read [here](https://www.elastic.co/blog/elastic-agent-and-fleet-make-it-easier-to-integrate-your-systems-with-elastic).

## Deployment and Configuration Guide

### Prerequisites

The integration package will be deployed and made available by Elastic on their cloud platform. To access it and use it accordingly, up and running Elastic stack along with the Elastic account will be needed to find, access, and deploy the package through Kibana.

The access to Kibana is available on your instance of Elastic stack, through the specific port and an URL based on your configuration. Steps to deploy and configure the package are provided below.

### Deployment and configuration 

Deployment is straight-forward through Kibana. You have two steps to take in order to deploy. The first step is to add an agent, and the second step is to add and configure integration.

To complete the first step, follow the instructions on this [link](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

To complete the second step, go to this [link](https://www.elastic.co/guide/en/fleet/7.15/integrations.htm#add-integration-under-integrations) and follow the instructions to Add integration to a policy.
Step 3 is where you should add any configuration options that are required.
Those parameters are authorization parameters against the Mimecast API (Application Key, Application ID, Access Key, and Secret Key), and they should be provided by a Mimecast representative for this integration.
Similarly, tapping the Advanced options link expands the form, allowing you to choose the time interval between two API requests as well as the API URL as the API endpoint. A Mimecast representative should also be able to give you with this information. The default interval value is 5m, but you can modify it. If you do, be sure to provide the time measurement unit (m for minute, s for seconds) rather than just a number.

Because parameters can differ, repeat the second step for each supported log you want to consume (A list of supported logs can be found in Log Types section below).
Ingesting all logs is enabled by default, but you can disable it by moving the blue slider next to the log name.

Once you save and confirm, ingesting logs will start automatically and you will be able to search for them.

## User guide

After you've finished setting and deploying integration, the elastic agent will begin ingesting data right away, and you'll be able to query it through Kibana. Instructions on how to do that can be found [here] (https://www.elastic.co/guide/en/beats/packetbeat/current/kibana-queries-filters.html).

### Understanding Logs

Here is the explanation of the typical log types we mentioned in the previous chapters, with relevant links toward the Mimecast documentation. 

#### Log Types

• Audit Events — more information about these logs [here] (https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-audit-events/).

• DLP Logs - more information about these logs [here] (https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-dlp-logs/). 

• TTP Attachment Protection Logs - learn more about these logs [here] (https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-ttp-attachment-protection-logs/).

• TTP Impersonation Protect Logs—  learn more about these logs [here] (https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-ttp-impersonation-protect-logs/). 

•	TTP URL Log - more about these logs [here](https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-ttp-url-logs/). 

•	Threat Intel Feed - more about these logs [here](https://integrations.mimecast.com/documentation/endpoint-reference/threat-intel/get-feed/). 

•	SIEM logs - more about these logs [here](https://integrations.mimecast.com/documentation/tutorials/understanding-siem-logs/).

## Dashboards

Kibana provides the ability to make a visual representation of the ingested log data. Based on the Mimecast documentation for available log types, it is possible to identify the most important data from the logs and display them within the Kibana dashboards. 

### Create and Edit Dashboard

ELK provides the ability to make a visual representation of the ingested log data. Based on the Mimecast documentation for available log types, it is possible to identify the most important data from the logs and display them within the Kibana dashboards.

For the reference on how to create or edit dashboard, please visit this [link](https://www.elastic.co/guide/en/kibana/current/dashboard.html). 

### Export/Import Dashboard

Kibana provides very useful feature – to export and import dashboards. To do that, follow these visualizations of the steps described:

To export:
 
1. Go to Kibana
2. Click on Management
3. Click on Saved Objects
4. Select each Dashboards, Searches and Visualizations you need and click on Export
5. Click on Export in top right corner

to Import:

1. Go to Kibana
2. Click on Management
3. Click on Saved Objects
4. Click on Import in top right corner
5. Select a file to import
6. Click Import button to Confirm

This integration also has already exported a few dashboards made as an example for you and you can see them below.

### Dashboard Examples

We made a couple dashboards to show you how they can be used. Steps to find them:

1. Go to Kibana
2. Click on Dashboards
3. Type "Mimecast" in Search Field

or you can follow [this] instructions.

There should be nine dashboards with the word [[Mimecast]] in the title.
Dashboards like those are examples of dashboards. 

## Logs

### AUDIT EVENTS

This is the `mimecast.audit_events` dataset.

{{event "audit_events"}}

{{fields "audit_events"}}

### DLP LOGS

This is the `mimecast.dlp_logs` dataset.

{{event "dlp_logs"}}

{{fields "dlp_logs"}}

### SIEM LOGS

This is the `mimecast.siem_logs` dataset.

{{event "siem_logs"}}

{{fields "siem_logs"}}

### TTP IMPERSONATION LOGS

This is the `mimecast.ttp_ip_logs` dataset.

{{event "ttp_ip_logs"}}

{{fields "ttp_ip_logs"}}

### TTP ATTACHMENT LOGS

This is the `mimecast.ttp_ap_logs` dataset.

{{event "ttp_ap_logs"}}

{{fields "ttp_ap_logs"}}

### TTP URL LOGS

This is the `mimecast.ttp_url_logs` dataset.

{{event "ttp_url_logs"}}

{{fields "ttp_url_logs"}}

### THREAT INTEL FEED MALWARE CUSTOMER

This is the `mimecast.threat_intel_malware_customer` dataset.

{{event "threat_intel_malware_customer"}}

{{fields "threat_intel_malware_customer"}}

### THREAT INTEL FEED MALWARE GRID

This is the `mimecast.threat_intel_malware_grid` dataset.

{{event "threat_intel_malware_grid"}}

{{fields "threat_intel_malware_grid"}}