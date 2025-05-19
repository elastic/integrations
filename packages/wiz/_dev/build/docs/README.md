# Wiz

[Wiz](https://www.wiz.io/) continuously prioritizes critical risks based on a deep cloud analysis across misconfigurations, network exposure, secrets, vulnerabilities, malware, and identities to build a single prioritized view of risk for your cloud.

This Wiz integration enables you to consume and analyze Wiz data within Elastic Security including issues, audit events, [misconfigurations](https://ela.st/cspm) [vulnerabilities](https://ela.st/cnvm) and defend which provides real-time threat detection based on runtime signals and cloud activity—giving you visibility and context for your cloud environments within Elastic Security.

## Data streams

The Wiz integration collects five types of data:

- **Audit** - The Audit log records key events within the Wiz platform, including logins and any mutation API calls executed in the Wiz portal (such as write, edit, delete, and save actions).

- **Cloud Configuration Finding** - A Cloud Configuration Finding is a result generated when a cloud resource does not pass a specific Cloud Configuration Rule.

- **Defend** - Detects and alerts on real-time cloud threats using runtime signals, logs, and Wiz’s security graph via webhook integrations.

- **Issue** - Issues represent active risks or threats identified in your cloud environment.

- **Vulnerability** - Vulnerabilities are weaknesses in computer systems that can be exploited by malicious attackers.

## Requirements

This integration supports using Elastic Agent or agentless ingestion of data.

## Elastic Agent

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.10.1**.
This module has been tested against the **Wiz API Version v1**.

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Setup

### To collect logs (Audit, Issue, Vulnerability, Cloud Configuration Findings) via GraphQL API:

### Get the Wiz API URL:

1. Go to your user profile.
2. Copy the **API Endpoint URL**.

### Steps to get the Client ID and Client Secret:

1. In the Wiz dashboard Navigate to Settings > Service Accounts.
2. Click Add Service Account.
3. Name the new service account, for example: Elastic Integration.
4. If you desire, narrow the scope of this service account to specific projects.
5. Select the permission read:resources and click Add Service Account.
6. Copy the Client Secret. Note that you won't be able to copy it after this stage.
7. Copy the Client ID, which is displayed under the Service Accounts page.

### Required scopes:

    | Data Stream   | Scope         |
    | ------------- | ------------- |
    | Audit         | admin:audit   |
    | Issue         | read:issues   |
    | Vulnerability | read:vulnerabilities |
    | Cloud Configuration Finding | read:cloud_configuration |
    | Cloud Configuration Finding Full Posture | read:cloud_configuration |

### To collect logs (Defend) via HTTP Endpoint:

1. Obtain the webhook URL
- Generate a webhook URL for the third-party product.
- (Recommended) Obtain or generate authentication info for the third-party product, either a username/password or an authentication token.

2. Add a webhook Integration in Wiz
- In Wiz, go to the Settings > Integrations page, then click Add Integration.
- Under SIEM & Automation Tools, click Webhook.
- On the New Integration page:
  - Enter a meaningful Name.
  - Set the Project Scope.
  - Paste the URL you generated earlier.
  - (Optional) Click Add Header, then enter the name and value of a custom header to add to every webhook.
  - Choose the type of Authentication to use:
    - None—Not recommended at all, but hey, it's your data.
    - Basic—Provide the Username and Password associated with your HTTP endpoint.
    - Token—Enter an authentication token generated by the application that will be called from the webhook.
  - For a more secure connection, enter a Client Certificate Authority and/or a Client Certificate to use in addition to whatever Authentication method was selected in the previous step.
- Click Add Integration.
- For more details, go to this [link](https://docs.wiz.io/docs/webhook-integration).

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type Wiz
3. Click on the "Wiz" integration from the search results.
4. Click on the "Add Wiz" button to add the integration.
5. Enable the input type corresponding to the log source you wish to collect from.
6. Configure all the required integration parameters, including the listen address, listen port, and authentication method along with its corresponding required fields for the HTTP Endpoint input type. For the CEL input type, ensure you provide the Client ID, Client Secret, URL, and Token URL to successfully retrieve logs.
7. Save the integration.

**Note:**
  - Vulnerability data is fetched for the previous day.
  - Custom headers are not supported in this integration. Only the standard Authorization header (e.g., Bearer token) is used for API requests.

## Logs Reference

### Audit

This is the `Audit` dataset.

#### Example

{{event "audit"}}

{{fields "audit"}}

### Cloud Configuration Finding

This is the `Cloud Configuration Finding` dataset.

#### Example

{{event "cloud_configuration_finding"}}

{{fields "cloud_configuration_finding"}}

### Cloud Configuration Finding Full Posture

This is the `Cloud Configuration Finding Full Posture` dataset.

#### Example

{{event "cloud_configuration_finding_full_posture"}}

{{fields "cloud_configuration_finding_full_posture"}}

### Defend

This is the `Defend` dataset.

#### Example

{{event "defend"}}

{{fields "defend"}}

### Issue

This is the `Issue` dataset.

#### Example

{{event "issue"}}

{{fields "issue"}}

### Vulnerability

This is the `Vulnerability` dataset.

#### Example

{{event "vulnerability"}}

{{fields "vulnerability"}}
