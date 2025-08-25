# ExtraHop

## Overview

[ExtraHop](https://www.extrahop.com/) delivers complete network visibility through its agentless RevealX NDR platform, empowering security teams to close detection gaps left by EDR, SIEM, and logs. ExtraHop provides the deep intelligence needed to detect threats faster, investigate with greater context, and respond at the speed of modern risk.

This integration enables you to collect investigation data via [ExtraHop RevealX 360 API](https://docs.extrahop.com/current/rx360-rest-api/), then visualise the data in Kibana.

## Data streams

The ExtraHop integration collects logs for one type of event.

**Investigation:** This datastream enables you to retrieve investigations that have been identified by the ExtraHop system.

>**Note**: For the **Investigation** Dashboard, ensure that the time range is aligned with the configured interval parameter to display accurate and consistent data.

## Requirements

### Agentless enabled integration
Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent based installation
Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Compatibility

For the REST API, this module has been tested against **ExtraHop RevealX 360 version 25.2 using the v1** API.

## Setup

### Enable the REST API for RevealX 360:

1. Log in to RevealX 360.
2. Click the System Settings icon at the top right of the page and then click **All Administration**.
3. Click **API Access**.
4. In the Manage API Access section, click **Enable**.
>**Note**: If you disable and then re-enable the REST API, the REST API might be unavailable for approximately 15 minutes due to DNS propagation, even if the Status section indicates that access is enabled. We recommend that you do not disable and re-enable the REST API often.

### To collect data from the ExtraHop RevealX 360 API:

1. Log in to RevealX 360.
2. Click the System Settings icon at the top right of the page and then click **All Administration**.
3. Click **API Access**.
4. Click **Create Credentials**.
5. In the **Name** field, type a name for the credentials.
6. In the **Privileges** field, specify a privilege level for the credentials. For more information about each privilege level, see [ExtraHop user account privileges](https://docs.extrahop.com/25.2/users-overview/#extrahop-user-account-privileges).
7. In the **Packet Access** field, specify whether you can retrieve packets and session keys with the credentials.
8. Click **Save**.
9. Copy REST API **Credentials**.

For more details, see [Documentation](https://docs.extrahop.com/current/rx360-rest-api/).

>**Note**: You must have system and access administration privileges.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **ExtraHop**.
3. Select the **ExtraHop** integration and add it.
4. Add all the required integration configuration parameters: URL, Client ID and Client Secret.
5. Save the integration.

## Logs reference

### Investigation

This is the `Investigation` dataset.

#### Example

{{event "investigation"}}

{{fields "investigation"}}
