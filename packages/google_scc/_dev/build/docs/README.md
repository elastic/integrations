# Google Security Command Center

## Overview

The [Google Security Command Center](https://cloud.google.com/security-command-center) integration allows users to monitor finding, audit, asset, and source. Security Command Center Premium provides comprehensive threat detection for Google Cloud that includes Event Threat Detection, Container Threat Detection, and Virtual Machine Threat Detection as built-in services.

Use the Google SCC integration to collect and parse data from the Google SCC REST API (finding, asset, and source) or GCP Pub/Sub (finding, asset, and audit). Then visualize that data through search, correlation, and visualization within Elastic Security.

## Data streams

The Google SCC integration collects four types of data: finding, audit, asset, and source.

**Finding** is a record of assessment data like security, risk, health, or privacy, that is ingested into Security Command Center for presentation, notification, analysis, policy testing, and enforcement. For example, a cross-site scripting (XSS) vulnerability in an App Engine application is a finding.

**Audit** logs created by Security Command Center as part of Cloud Audit Logs.

**Asset** lists assets with time and resource types and returns paged results in response.

**Source** is an entity or a mechanism that can produce a finding. A source is like a container of findings that come from the same scanner, logger, monitor, and other tools.

## Compatibility

This module has been tested against the latest Google SCC API version **v1**.

## Requirements

### Agentless enabled integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Google SCC service account

To create your Google SCC service account, you have to follow [these steps](https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount) and the following permissions are required: 
- Cloud Asset Viewer at Organization Level
- Pub/Sub Subscriber at Project Level
- Security Center Admin Editor at Organization Level
- **Security Command Center API** and **Cloud Asset API** must be enabled.

This integration will make use of the following *oauth2 scope*:

- `https://www.googleapis.com/auth/cloud-platform`

Once Service Account credentials are downloaded as a JSON file, then the integration can be setup to collect data.

If installing in GCP-Cloud Environment, No need to provide any credentials and make sure the account linked with the VM has all the required IAM permissions. Steps to [Set up Application Default Credentials](https://cloud.google.com/docs/authentication/provide-credentials-adc).

## Setup

### Create GCP Pub/Sub

1. [Create Topic for Pub/sub](https://cloud.google.com/pubsub/docs/create-topic#create_a_topic).
2. [Create Subscription for topic](https://cloud.google.com/pubsub/docs/create-subscription#create_subscriptions)

### Collect data from GCP Pub/Sub

1. [Configure to export finding to GCP Pub/Sub](https://cloud.google.com/security-command-center/docs/how-to-notifications).
2. [Configure to export asset to GCP Pub/Sub](https://cloud.google.com/asset-inventory/docs/monitoring-asset-changes).
3. [Configure to export audit to GCP Pub/Sub](https://cloud.google.com/logging/docs/export/configure_export_v2?_ga=2.110932226.-66737431.1679995682#overview).

**NOTE**:
   - **Sink destination** must be **Pub/Sub topic** while exporting audit logs to GCP Pub/Sub.
   - Create unique Pub/Sub topic per data-stream.

### Enable the integration in Elastic

1. In Kibana go to **Management > Integrations**.
2. In "Search for integrations" search bar, type **Google Security Command Center**.
3. Click on the **Google Security Command Center** integration from the search results.
4. Click on the **Add Google Security Command Center** Integration button to add the integration.
5. While adding the integration, if you want to **collect logs via Rest API**, turn on the toggle and then put the following details:
   - credentials type
   - credentials JSON/file
   - parent type
   - id
   - To collect **asset logs**, put the following details:
      - content type

   or if you want to **collect logs via GCP Pub/Sub**, turn on the toggle and then put the following details:
   - credentials type
   - credentials JSON/file
   - project id
   - To collect **asset, audit, or finding logs**, put the following details:
      - topic
      - subscription name 

## Logs reference

### Asset

This is the `Asset` dataset.

#### Example

{{event "asset"}}

{{fields "asset"}}

### Finding

This is the `Finding` dataset.

#### Example

{{event "finding"}}

{{fields "finding"}}

### Source

This is the `Source` dataset.

#### Example

{{event "source"}}

{{fields "source"}}

### Audit

This is the `Audit` dataset.

#### Example

{{event "audit"}}

{{fields "audit"}}