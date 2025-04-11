# BeyondTrust PRA

[BeyondTrust Privileged Remote Access (PRA)](https://www.beyondtrust.com/products/privileged-remote-access) is a solution designed to securely manage and control remote access to critical systems for privileged users, such as administrators, IT personnel, and third-party vendors. PRA is part of our broader suite of Privileged Access Management (PAM) solutions. It provides real-time session monitoring, auditing, and recording, which helps you maintain compliance and detect any unauthorized or risky activities. By enforcing least-privilege access and supporting third-party vendor management, it reduces the attack surface and enhances overall security for remote operations.

## Compatibility

This integration is compatible with **BeyondTrust PRA 24.1.x** and has been tested against the **API Version 1.24.1** for REST API support.

## Data streams

This integration collects the following logs:

- **[Access Session](https://docs.beyondtrust.com/pra/docs/reporting#accesssession)** - Enables users to collect event logs occurred during each AccessSession using the REST API.

## Requirements

### Agentless Enabled Integration
Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent Based Installation
- Elastic Agent must be installed
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data from the GCP Pub/Sub or REST API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

#### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

#### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

#### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it is installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

#### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

## Setup

### To collect data from the BeyondTrust PRA API:
- If the integration client is not installed follow this [doc](https://docs.beyondtrust.com/pra/docs/integration-client) to setup integration client and add database as guided.
- After having installed integration client & created the settings database, you are prompted to enter information for one or more BeyondTrust PRA sites from which the integration client extracts session data. Click **OK** to continue.
- If you wish to update or add a site, select **Site Configuration** from the integration client Setup dropdown.
- When the **Site Configuration** dialog appears, click the **New button** to input your BeyondTrust PRA site information.
- Enter a name for this site configuration and the URL of the site (note that **https://** should NOT be included)
- For **BeyondTrust PRA** sites on version 16.1 and above, you must provide the **Client ID** and **Client Secret** for an API account with permission to view reports and recordings. If you plan to pull site backups, backup API permissions must also be enabled for the API account. Click Edit on the API user account to identify the OAuth Client ID, and click Generate New Client Secret and record the secret.
- Optionally, you may apply a password to any backups created. If you do choose to set a password, you must provide this password to revert to the backup.
- Test the supplied credentials and then click **Save**.
- When you have finished entering your BeyondTrust site information, click **Next**.
    - **Note**: For BeyondTrust PRA sites running version 16.1 and above, if the account's password is reset, the integration client stops pulling data until the site configuration is updated. To prevent this break, it is recommended that you create a special account for the integration client with only permissions needed to retrieve the desired data and with a password set to never expire.
    - Integration client supports more than one site. If session data from additional sites needs to be extracted, click the **New** button again and repeat the configuration process. The **host_name** in the session table distinguishes the data.

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `BeyondTrust PRA`.
3. Select the "BeyondTrust PRA" integration from the search results.
4. Select "Add BeyondTrust PRA" to add the integration.
5. Add all the required integration configuration parameters, including the URL, Client ID, Client Secret, Session Timeout, Interval, and Initial Interval, to enable data collection.
6. Select "Save and continue" to save the integration.

## Logs

### Access Session

This is the `Access Session` dataset.

#### Example

{{fields "access_session"}}

{{event "access_session"}}
