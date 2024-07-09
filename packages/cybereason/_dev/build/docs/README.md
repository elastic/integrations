# Cybereason

## Overview

[Cybereason](https://www.cybereason.com/) is a cybersecurity company that specializes in endpoint detection and response (EDR) solutions to help organizations detect and respond to cyber threats. Cybereason's goal is to provide a comprehensive cybersecurity solution that helps organizations defend against a wide range of cyber threats, including malware, ransomware, and advanced persistent threats (APTs).

Use the Cybereason integration to collect and parse data from the REST APIs. Then visualize that data in Kibana.

## Compatibility

This module has been tested against the latest Cybereason On-Premises version **23.2**.

## Data streams

The Cybereason integration collects six types of logs: Logon Session, Malop Connection, Malop Process, Malware, Poll Malop and Suspicions Process.

**[Logon Session](https://api-doc.cybereason.com/en/latest/APIReference/QueryAPI/queryElementFeatures.html#logon-session-edr)** - This data stream helps security teams monitor and analyze logon sessions within their network, identifying potential threats and taking appropriate action to mitigate risks.

**[Malop Connection](https://api-doc.cybereason.com/en/latest/APIReference/QueryAPI/queryElementFeatures.html#connection-edr-and-xdr)** - This data stream provides detailed insights into network connections observed by the endpoint detection and response (EDR) system.

**[Malop Process](https://api-doc.cybereason.com/en/latest/APIReference/QueryAPI/queryElementFeatures.html#malop-process-edr)** - This data stream provides details about malicious processes detected within their environment, aiding in the detection and mitigation of security threats.

**[Malware](https://api-doc.cybereason.com/en/latest/APIReference/MalwareAPI/queryMalwareTypes.html#querymalware)** - This data stream provides detailed information about a malware detection event, including the detected file, its type, detection method, and additional metadata for analysis and response.

**[Poll Malop](https://api-doc.cybereason.com/en/latest/APIReference/MalopAPI/getMalopsMalware.html#getmalopsmalware)** - This data stream provides comprehensive information about Malops detected by Cybereason's EDR system, enabling security teams to analyze and respond to potential threats effectively.

**[Suspicions Process]()** - This data stream provides detailed information about processes that are suspected or deemed malicious within the endpoint detection and response (EDR) system.

**NOTE**: Suspicions Process has the same endpoint as the first three data streams, we have added a filter - `hasSuspicions : true` and some custom fields to get the logs related to suspicions.

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

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.12.0**.

## Setup

### To collect logs through REST API, follow the below steps:

- Visit [this page](https://www.cybereason.com/platform/bundles) to deploy a Cybereason instance in your environment.
- Once deployed, you'll obtain the parameters such as host, port, username and password for configuring Cybereason integration within your Elasticsearch environment.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type Cybereason.
3. Click on the "Cybereason" integration from the search results.
4. Click on the Add Cybereason Integration button to add the integration.
5. While adding the integration, please enter the following details to collect logs via REST API:
   - Host
   - Port
   - Username
   - Password
   - Initial Interval
   - Interval
   - Batch Size

## Logs Reference

### Logon Session

This is the `Logon Session` dataset.

#### Example

{{event "logon_session"}}

{{fields "logon_session"}}

### Malop Connection

This is the `Malop Connection` dataset.

#### Example

{{event "malop_connection"}}

{{fields "malop_connection"}}

### Malop Process

This is the `Malop Process` dataset.

#### Example

{{event "malop_process"}}

{{fields "malop_process"}}

### Malware

This is the `Malware` dataset.

#### Example

{{event "malware"}}

{{fields "malware"}}

### Poll Malop

This is the `Poll Malop` dataset.

#### Example

{{event "poll_malop"}}

{{fields "poll_malop"}}

### Suspicions Process

This is the `Suspicions Process` dataset.

#### Example

{{event "suspicions_process"}}

{{fields "suspicions_process"}}