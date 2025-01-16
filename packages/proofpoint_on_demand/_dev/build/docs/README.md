# Proofpoint On Demand

Proofpoint on Demand is a cloud-based cybersecurity platform that offers a wide range of services to protect businesses against cyber threats. This includes email security, threat intelligence, information protection, and compliance solutions. The Proofpoint on Demand integration for Elastic provides insight into the functioning and effectiveness of your email security policies, allowing you to make informed decisions to improve security posture.

The Proofpoint On Demand integration collects data for Audit, Mail, and Message logs utilizing the Secure WebSocket (WSS) protocol for log streaming.

## Data streams

The Proofpoint On Demand integration collects data for the following three events:

- **Audit**  
- **Mail**  
- **Message**

## Requirements

Elastic Agent must be installed. For more details and installation instructions, please refer to the [Elastic Agent Installation Guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

There are several options for installing and managing Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

Please note, there are minimum requirements for running Elastic Agent. For more information, refer to the  [Elastic Agent Minimum Requirements](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html#elastic-agent-installation-minimum-requirements).

## Setup

### To collect data from the Proofpoint On Demand Log Service:

The **Cluster ID** is displayed in the upper-right corner of the management interface, next to the release number. Proofpoint will provide the token for each cluster.

**NOTE**: Proofpoint On Demand Log service requires a Remote Syslog Forwarding license. Please refer the [documentation](https://proofpointcommunities.force.com/community/s/article/Proofpoint-on-Demand-Pod-Log-API) on how to enable it.

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Proofpoint On Demand`.
3. Select the "Proofpoint On Demand" integration from the search results.
4. Select "Add Proofpoint On Demand" to add the integration.
5. Add all the required integration configuration parameters, including Cluster ID and Access Token, to enable data collection.
6. Click on "Save and continue" to save the integration.

## Logs Reference

### Audit

This is the `Audit` dataset.

#### Example

{{event "audit"}}

{{fields "audit"}}

### Mail

This is the `Mail` dataset.

#### Example

{{event "mail"}}

{{fields "mail"}}

### Message

This is the `Message` dataset.

#### Example

{{event "message"}}

{{fields "message"}}