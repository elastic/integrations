# Nozomi Networks

## Overview

[Nozomi Networks](https://www.nozominetworks.com/) is a global leader in OT and IoT cybersecurity, delivering unmatched visibility, real-time threat detection, and AI-powered analysis to safeguard critical infrastructure. Trusted across industries, Nozomi helps organizations protect mission-critical environments by combining deep network and endpoint visibility with rapid, intelligent incident response—ensuring security, compliance, and operational resilience.

For this integration, data should be collected from Nozomi’s Vantage platform via REST APIs.

## Data streams

The Nozomi Networks integration collects logs for eight types of events.

**Alert:** Alert allows collecting Alert Log Events, which are generated when the system detects unusual or potentially harmful activity. These events are categorized by severity and help monitor network security and operations.

**Asset:** Asset allows collecting Asset Log Events, which are generated to capture details of all physical components and systems in the local network, including their attributes, types, and relationships for improved visibility and management.

**Audit:** Audit allows collecting Audit Log Events, which are generated whenever a user performs actions such as login, logout, or configuration changes, capturing the IP address and username of the user for tracking and accountability.

**Health:** Health allows collecting Health Log Events, which provide status updates and condition changes of sensors to monitor their operational state and ensure system reliability.

**Node:** Node allows collecting Node Log Events, which are generated to capture details of individual network entities, such as computers or controllers, providing insights into their communication protocols and roles within the network.

**Node CVE:** Node CVE allows collecting vulnerability events by matching network nodes against current Common Vulnerabilities and Exposures (CVEs), helping to identify security risks.

**Session:** Sessions allow collecting session events, capturing the start and end of connections between network nodes, including detailed information about the messages exchanged during these sessions.

**Variable:** Variables allow collecting data extracted via deep packet inspection (DPI) from monitored systems, providing detailed insights into the variables associated with each asset.

## Requirements

### Agentless-enabled integration
Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation
Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Compatibility

For Rest API, this module has been tested against the **N2OS 25.1.0** version.

## Setup

### Collect data from the Nozomi Networks API:

1. Navigate to your **Profile > API Keys** in the Vantage UI (top-right corner).
2. Click on **Add** API Keys.
3. Optionally Add a **Description** and **Allowed IPs**.
4. Select the appropriate **Organization**.
5. Click **Generate**.
6. Copy **Key Name** and **Key Token**.

**Required Roles by Endpoint:**

| **Endpoint**   | **Role**                                                  |
|----------------|-----------------------------------------------------------|
| Audit          | Superobserver                                             |
| Alert          | Alerts Operator, Observer, Superobserver                  |
| Asset          | Assets Operator, Observer, Superobserver                  |
| Health         | Superobserver                                             |
| Node           | Superobserver                                             |
| Node CVE       | Vulnerabilities Operator, Observer, Superobserver         |
| Session        | Superobserver                                             |
| Variable       | Superobserver                                             |

For more details, see [Nozomi Vantage API Key](https://technicaldocs.nozominetworks.com/products/vantage/topics/administration/teams/t_vantage_admin_teams_api-keys_generate-1.html) and [Role Documentation](https://technicaldocs.nozominetworks.com/products/vantage/topics/administration/teams/r_vantage_admin_teams_groups_roles-permissions.html).

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **Nozomi Networks**.
3. Select the **Nozomi Networks** integration and add it.
4. Add all the required integration configuration parameters: URL, Username and Password.
5. Save the integration.

## Logs reference

### Alert

This is the `Alert` dataset.

#### Example

{{event "alert"}}

{{fields "alert"}}

### Asset

This is the `Asset` dataset.

#### Example

{{event "asset"}}

{{fields "asset"}}

### Audit

This is the `Audit` dataset.

#### Example

{{event "audit"}}

{{fields "audit"}}

### Health

This is the `Health` dataset.

#### Example

{{event "health"}}

{{fields "health"}}

### Node

This is the `Node` dataset.

#### Example

{{event "node"}}

{{fields "node"}}

### Node CVE

This is the `Node CVE` dataset.

#### Example

{{event "node_cve"}}

{{fields "node_cve"}}

### Session

This is the `Session` dataset.

#### Example

{{event "session"}}

{{fields "session"}}

### Variable

This is the `Variable` dataset.

#### Example

{{event "variable"}}

{{fields "variable"}}