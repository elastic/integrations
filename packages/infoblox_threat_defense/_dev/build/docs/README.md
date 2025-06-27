# Infoblox Threat Defense

## Overview

[Infoblox Threat Defense](https://www.infoblox.com/products/threat-defense/) is a DNS-based security solution that protects networks from cyber threats by detecting and blocking malicious domain activity in real time. It uses threat intelligence, DNS firewalling, and behavioral analytics to identify threats like malware, phishing, and data exfiltration at the DNS layer — often before they reach endpoints or firewalls. Available as a cloud-native platform (BloxOne Threat Defense), it integrates with security tools (like SIEMs and firewalls) and supports both on-prem and hybrid deployments.

This integration supports CEF-formatted logs transmitted through a syslog server over TCP, UDP, or TLS protocols.

## Data streams

The Infoblox Threat Defense integration collects the following types of events.

- **Audit:** - The audit log reports all administrative activities performed by specific user accounts.

- **Service:** - The Service Log reports all service events.

- **Atlas Notifications:** - Atlas Notifications reports all internal notification events.

- **SOC Insights:** - The SOC Insights log reports information about SOC Insights security events.

- **Threat Defense Query/Response (TD DNS):** - The Threat Defense Query/Response Log reports DNS query requests and responses in Infoblox Threat Defense.

- **Threat Defense Threat Feeds Hit (TD RPZ):** - The Threat Defense Threat Feeds Hit Log reports Infoblox Threat Defense feeds hit information.

- **DDI DHCP Lease (DDI DHCP):** - The DDI DHCP Lease Log reports information about Dynamic Host Configuration Protocol (DHCP) lease assignments and terminations.

- **DDI Query/Response (DDI DNS):** - The DDI Query/Response Log reports DNS query requests and responses in Universal DDI.

**NOTE**: While the Infoblox Threat Defense integration collects logs for various event types, we have consolidated them into a single data stream named `event`.

## Requirements

### Agent-based deployment

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data through the TCP/UDP and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

#### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

#### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

#### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

#### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent. For more information, refer to the Elastic Agent [installation guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

## Setup

### To collect data from the Infoblox Threat Defense:

1. To collect logs through the syslog server, you need to deploy a Data Connector VM by following the instructions provided [here](https://docs.infoblox.com/space/BloxOneCloud/35429862/Deploying+the+Data+Connector+Solution).
2. Once the Data Connector is successfully deployed, you need to configure the traffic flow to forward logs to your syslog server. Refer to this [link](https://docs.infoblox.com/space/BloxOneCloud/35397475/Configuring+Traffic+Flows) for guidance.

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Infoblox Threat Defense`.
3. Select "Infoblox Threat Defense" integration from the search results.
4. Click on the "Add Infoblox Threat Defense" button to add the integration.
5. Enable the data collection mode from the following: TCP, or UDP.
6. Add all the required configuration parameters, such as listen address and listen port for the TCP and UDP, and ssl for the TLS.
8. Click on "Save and Continue" to save the integration.

## Logs reference

### Event

This is the `Event` dataset.

**NOTE**: The `InfobloxDHCPOptions` field will not be populated because it contains a special pattern with special characters that `decode_cef` cannot parse. As a result, this field will be dropped.

#### Example

{{event "event"}}

{{fields "event"}}
