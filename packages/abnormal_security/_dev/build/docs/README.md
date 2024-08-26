# Abnormal Security

Abnormal Security is a behavioral AI-based email security platform that learns the behavior of every identity in a cloud email environment and analyzes the risk of every event to block even the most sophisticated attacks.

The Abnormal Security integration collects data for AI Security Mailbox (formerly known as Abuse Mailbox), Audit, Case, and Threat logs using REST API.

## Data streams

The Abnormal Security integration collects four types of logs:

**[AI Security Mailbox](https://app.swaggerhub.com/apis-docs/abnormal-security/abx/1.4.3#/AI%20Security%20Mailbox%20(formerly%20known%20as%20Abuse%20Mailbox))** - Get details of AI Security Mailbox.

**[Audit](https://app.swaggerhub.com/apis-docs/abnormal-security/abx/1.4.3#/Audit%20Logs)** - Get details of Audit logs for Portal.

**[Case](https://app.swaggerhub.com/apis-docs/abnormal-security/abx/1.4.3#/Cases)** - Get details of Abnormal Cases.

**[Threat](https://app.swaggerhub.com/apis-docs/abnormal-security/abx/1.4.3#/Threats)** - Get details of Abnormal Threat Logs.

## Requirements

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html#_minimum_requirements).

## Setup

### To collect data from the Abnormal Security Client API:

#### Step 1: Go to Portal
* Visit the [Abnormal Security Portal](https://portal.abnormalsecurity.com/home/settings/integrations) and click on the `Abnormal REST API` setting.

#### Step 2: Generating the authentication token
* Retrieve your authentication token. This token will be used further in the Elastic integration setup to authenticate and access different Abnormal Security Logs.

#### Step 3: IP allowlisting
* Abnormal Security requires you to restrict API access based on source IP. So in order for the integration to work, user needs to update the IP allowlisting to include the external source IP of the endpoint running the integration via Elastic Agent.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type Abnormal Security.
3. Click on the "Abnormal Security" integration from the search results.
4. Click on the "Add Abnormal Security" button to add the integration.
5. Add all the required integration configuration parameters, including Access Token, Interval, Initial Interval and Page Size to enable data collection.
6. Click on "Save and continue" to save the integration.

**Note**: By default, the URL is set to `https://api.abnormalplatform.com`. We have observed that Abnormal Security Base URL changes based on location so find your own base URL.

## Logs reference

### AI Security Mailbox

This is the `ai_security_mailbox` dataset.

#### Example

{{event "ai_security_mailbox"}}

{{fields "ai_security_mailbox"}}

### Audit

This is the `audit` dataset.

#### Example

{{event "audit"}}

{{fields "audit"}}

### Case

This is the `case` dataset.

#### Example

{{event "case"}}

{{fields "case"}}

### Threat

This is the `threat` dataset.

#### Example

{{event "threat"}}

{{fields "threat"}}
