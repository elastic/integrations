# Qualys Vulnerability Management, Detection and Response (VMDR)

This [Qualys VMDR](https://www.qualys.com/apps/vulnerability-management-detection-response/) integration is a cloud-based service that gives you immediate, global visibility into where your IT systems might be vulnerable to the latest Internet threats and how to protect them. It helps you to continuously identify threats and monitor unexpected changes in your network before they turn into breaches.

The Qualys VMDR integration uses REST API mode to collect data. Elastic Agent fetches data via API endpoints.

## Compatibility

This module has been tested against the latest Qualys VMDR version **v2**.

## Data streams

The Qualys VMDR integration collects data for the following three events:

| Event Type           |
|----------------------|
| Asset Host Detection |
| Knowledge Base       |
| User Activity Log    |

Reference for [Rest APIs](https://qualysguard.qg2.apps.qualys.com/qwebhelp/fo_portal/api_doc/index.htm) of Qualys VMDR.

Starting from Qualys VMDR integration version 6.0, the `Asset Host Detection` data stream includes enriched vulnerabilities data from Qualys Knowledge Base API.

## Requirements

### Agentless-enabled integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Permissions

#### Asset host detection

| Role                    | Permission                                     |
|-------------------------|------------------------------------------------|
| _Managers_              | All VM scanned hosts in subscription           |
| _Unit Managers_         | VM scanned hosts in user’s business unit       |
| _Scanners_              | VM scanned hosts in user’s account             |
| _Readers_               | VM scanned hosts in user’s account             |

#### Knowledge base

_Managers_, _Unit Managers_, _Scanners_, _Readers_ have permission to download vulnerability data from the KnowledgeBase.

#### User activity log

| Role                    | Permission                                     |
|-------------------------|------------------------------------------------|
| _Managers_              | All actions taken by all users                 |
| _Unit Managers_         | Actions taken by users in their business unit  |
| _Scanners_              | Own actions only                               |
| _Readers_               | Own actions only                               |

## Setup

### Collect data through REST API

Assuming that you already have a Qualys user account, to identify your Qualys platform and get the API URL, check the [Qualys documentation](https://www.qualys.com/platform-identification/).
Alternatively, to get the API URL log in to your Qualys account and go to **Help** > **About**. You’ll find your URL under **Security Operations Center (SOC)**.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **Qualys VMDR**.
3. Select the **Qualys VMDR** integration and add it.
4. While adding the integration, if you want to collect Asset Host Detection data via REST API, then you have to put the following details:
   - username
   - password
   - url
   - interval
   - input parameters
   - batch size

   or if you want to collect Knowledge Base data via REST API, then you have to put the following details:
   - username
   - password
   - url
   - initial interval
   - interval
   - input parameters

   or if you want to collect User Activity log data via REST API, then you have to put the following details:
   - username
   - password
   - url
   - initial interval
   - interval
5. Save the integration.

**NOTE**: By default, the input parameter is set to `action=list`.

## Data reference

### Asset host detection

This is the `Asset Host Detection` dataset.

#### Example

{{event "asset_host_detection"}}

{{fields "asset_host_detection"}}

### Knowledge base

This is the `Knowledge Base` dataset.

#### Example

{{event "knowledge_base"}}

{{fields "knowledge_base"}}

### User activity

This is the `User Activity` dataset. It connects to an [API](
https://docs.qualys.com/en/vm/api/users/index.htm#t=activity%2Fexport_activity.htm)
that exports the user activity log. 

#### Example

{{event "user_activity"}}

{{fields "user_activity"}}