# ExtraHop Integration for Elastic

## Overview

[ExtraHop](https://www.extrahop.com/) delivers complete network visibility through its agentless RevealX NDR platform, empowering security teams to close detection gaps left by EDR, SIEM, and logs. ExtraHop provides the deep intelligence needed to detect threats faster, investigate with greater context, and respond at the speed of modern risk.

The ExtraHop integration for Elastic allows you to collect logs from [ExtraHop RevealX 360 API](https://docs.extrahop.com/current/rx360-rest-api/), then visualise the data in Kibana.

### Compatibility

The ExtraHop integration is compatible with `RevealX 360 version 25.2` and `v1` version of ExtraHop RevealX 360 APIs.

### How it works

This integration periodically queries the ExtraHop RevealX 360 API to retrieve detections.

## What data does this integration collect?

This integration collects log messages of the following types:

- `Detection`: Collects detections that have been identified by the ExtraHop system.[Detection API endpoint](https://docs.extrahop.com/current/rx360-rest-api/#detections).

### Supported use cases
Integrating ExtraHop with Elastic SIEM converts high-fidelity wire-data detections into actionable insights, giving real-time visibility into risks mapped to tactics and techniques. This integration enhances threat hunting, speeds up incident response, and closes network visibility gaps. Kibana dashboards further support analysts with detailed breakdowns by detection type, category, status, resolution, and assignee, enabling efficient triage and streamlined investigations.

## What do I need to use this integration?

### From Elastic

This integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From ExtraHop

To collect data through the ExtraHop APIs, `API Access` must be enabled. Authentication is handled using a `Client ID` and `Client Secret`, which serve as the required credentials. Any requests made without credentials will be rejected by the ExtraHop APIs.

#### Enable API Access:

1. Log in to RevealX 360.
2. Click the System Settings icon at the top right of the page and then click **All Administration**.
3. Click **API Access**.
4. In the Manage API Access section, click **Enable**.
>**Note**: If you disable and then re-enable the REST API, the REST API might be unavailable for approximately 15 minutes due to DNS propagation, even if the Status section indicates that access is enabled. We recommend that you do not disable and re-enable the REST API often.

#### Obtain `Credentials`:

1. Log in to RevealX 360.
2. Click the System Settings icon at the top right of the page and then click **All Administration**.
3. Click **API Access**.
4. Click **Create Credentials**.
5. In the **Name** field, type a name for the credentials.
6. In the **Privileges** field, specify a privilege level for the credentials. For more information about each privilege level, see [ExtraHop user account privileges](https://docs.extrahop.com/25.2/users-overview/#extrahop-user-account-privileges).
7. In the **Packet Access** field, specify whether you can retrieve packets and session keys with the credentials.
8. Click **Save**.
9. Copy REST API **Credentials**.

For more details, check [Documentation](https://docs.extrahop.com/current/rx360-rest-api/).

>**Note**: You must have system and access administration privileges.

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **ExtraHop**.
3. Select the **ExtraHop** integration from the search results.
4. Select **Add ExtraHop** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect ExtraHop logs via API**, you'll need to:

        - Configure **URL**, **Client ID**, and **Client Secret**.
        - Enable/Disable the required datasets.
        - For each dataset, adjust the integration configuration parameters if required, including the Initial Interval, Interval, etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **extrahop**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

#### Transforms healthy

1. In the top search bar in Kibana, search for **Transforms**.
2. Select the **Data / Transforms** from the search results.
3. In the search bar, type **extrahop**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

#### Detection

{{fields "detection"}}

### Example event

#### Detection

{{event "detection"}}

### Inputs used

These inputs can be used in this integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration datasets use the following APIs:

- `Detections`: [RevealX 360 API](https://docs.extrahop.com/current/rx360-rest-api/#detections).
