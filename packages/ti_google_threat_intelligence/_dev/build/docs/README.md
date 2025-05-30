# Google Threat Intelligence

## Overview

[Google Threat Intelligence](https://gtidocs.virustotal.com/) is a security solution that helps organizations detect, analyze, and mitigate threats. It leverages Google's global telemetry, advanced analytics, and vast infrastructure to provide actionable insights. Key features include threat detection, malware and phishing analysis, and real-time threat alerts.

Google Threat Intelligence uses the **[Threat List API](https://gtidocs.virustotal.com/reference/api-overview)** to deliver hourly data chunks. The Threat Lists feature allows customers to consume **Indicators of Compromise (IOCs)** categorized by various threat types.

## Threat List API Feeds

The Threat List API provides the following types of threat feeds:

- **Ransomware**
- **Malicious Network Infrastructure**
- **Malware**
- **Threat Actor**
- **Daily Top Trending**
- **Mobile**
- **OS X**
- **Linux**
- **Internet of Things (IoT)**
- **Cryptominers**
- **Phishing**
- **First Stage Delivery Vectors**
- **Vulnerability Weaponization**
- **Infostealers**

## GTI Subscription Tiers

Customers can access a subset of the available threat lists based on their **Google Threat Intelligence (GTI) tier**:

- **GTI Standard**: Ransomware, Malicious Network Infrastructure
- **GTI Enterprise**: Ransomware, Malicious Network Infrastructure, Malware, Threat Actor, Daily Top Trending
- **GTI Enterprise+**: Access to all available threat lists

## Data Streams

Data collection is available for all four feed types: `Linux`, `Malicious Network Infrastructure`, `Malware`, `Mobile` and `OS X`, each with a separate data stream. By default, **Malicious Network Infrastructure** is enabled. Users can enable additional data streams based on their GTI subscription tier. If a user enables data collection for a data stream they do not have access to, it will result in an error log on the **Discover** page.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

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
**Note:** Please make only the threat feed types you have the privilege to access are enabled.

## Logs Reference

### Linux

This is the `Linux` dataset.

#### Example

{{event "linux"}}

{{fields "linux"}}

### Malicious Network Infra

This is the `Malicious Network Infra` dataset.

#### Example

{{event "malicious_network_infrastructure"}}

{{fields "malicious_network_infrastructure"}}

### Malware

This is the `Malware` dataset.

#### Example

{{event "malware"}}

{{fields "malware"}}

### Mobile

This is the `Mobile` dataset.

#### Example

{{event "mobile"}}

{{fields "mobile"}}

### OS X

This is the `OS X` dataset.

#### Example

{{event "osx"}}

{{fields "osx"}}
