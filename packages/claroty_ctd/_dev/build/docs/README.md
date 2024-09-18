# Claroty CTD

## Overview

[Claroty CTD](https://claroty.com/industrial-cybersecurity/ctd) is a robust solution that delivers comprehensive cybersecurity controls for industrial and government environments. The company’s comprehensive platform connects seamlessly with customers' existing infrastructure and programs while providing a full range of industrial cybersecurity controls for visibility, threat detection, risk and vulnerability management, and secure remote access all with a significantly reduced total cost of ownership.

Claroty CTD integration collects and parses data using a Syslog server and REST API, then visualizes it in Kibana.

## Compatibility

This module has been tested against the latest Claroty CTD version **4.10.0**.

## Data streams

The Claroty CTD integration collects 7 types of message:

### Supported via Syslog

**[Activity Log]** - The Activity Log records activities performed in CTD in the last year by users and by the system.

**[Alerts]** - Qualified and quantified event or chain of events which are based on various risk factors. Further categorized as either Security Alerts or Integrity Alerts depending on the nature of the alert.

**[Events]** - Events are the foundation of the CTD’s threat detection module. They are conversations or activities logged by various engines in CTD, which are then categorized as either risky (Alert or OT Alert) or non-risky (Non-Risky Change or an OT Operation) events.

**[Health Monitoring]** - Scheduled periodic system Health Monitoring information can be sent via Syslog messages.This can be used for forwarding real-time system health status information to external monitoring tools and for alert generation.

**[Insights]** - The CTD system identifies assets affected by potential security risks, based on a variety of out-of-the-box use cases, and groups them together into insights. The purpose of the insights is to provide knowledge regarding these security risks and indicate mitigation measures, which will improve the overall security posture of the organization.

### Supported via REST API

**[Assets]** - Asset is any distinguishable network entity. CTD can discover an extensive range of assets in three classes - OT, IT, and IoT.

**[Baseline]** - Baseline is a collection of valid network behaviors. An individual baseline represents a command or an instance of communication between two assets.

**NOTE**: The Claroty CTD integration collects logs for different events, but for syslog input we have combined all of those in one data stream named `event`.

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data through the Syslog server and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

## Setup

### To collect data via TCP/UDP, follow the below steps:

1. To set up Claroty CTD, refer to the [Installation Guide](https://portal.claroty.com/prm/English/s/assets?id=696859).
2. To configure the syslog message types in Claroty CTD, refer to the [Administration Guide](https://portal.claroty.com/prm/English/s/assets?id=696857).
3. Claroty CTD supports multiple message formats, including RFC5424, CEF, and CEF(Latest). Currently, we recommend using the CEF(Latest) message format for optimal integration with Elastic.

### To collect data via REST API, follow the below steps:

1. To set up Claroty CTD, refer to the [Installation Guide](https://portal.claroty.com/prm/English/s/assets?id=696859).
2. Obtain the credentials (username, password, and URL) that are generated during the setup process.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type Claroty CTD.
3. Select "Claroty CTD" integration from the search results.
4. To collect logs via TCP or UDP, please enter the following details:
   - Listen Address
   - Listen Port

   To collect logs via REST API, please enter the following details:
   - Username
   - Password
   - URL

## Logs Reference

### Event

This is the `event` dataset.

#### Example

{{event "event"}}

{{fields "event"}}

### Assets

This is the `asset` dataset.

#### Example

{{event "asset"}}

{{fields "asset"}}

### Baseline

This is the `baseline` dataset.

#### Example

{{event "baseline"}}

{{fields "baseline"}}
