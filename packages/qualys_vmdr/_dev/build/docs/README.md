# Qualys Vulnerability Management, Detection and Response (VMDR)

This [Qualys VMDR](https://www.qualys.com/apps/vulnerability-management-detection-response/) integration is a cloud-based service that gives you immediate, global visibility into where your IT systems might be vulnerable to the latest Internet threats and how to protect them. It helps you to continuously identify threats and monitor unexpected changes in your network before they turn into breaches.

The Qualys VMDR integration uses REST API mode to collect data. Elastic Agent fetches data via API endpoints.

## Compatibility

This module has been tested against the latest Qualys VMDR version **v2**.

## Data streams

The Qualys VMDR integration collects data for the following two events:

| Event Type           |
|----------------------|
| Asset Host Detection |
| Knowledge Base       |
| User Activity Log    |

Reference for [Rest APIs](https://qualysguard.qg2.apps.qualys.com/qwebhelp/fo_portal/api_doc/index.htm) of Qualys VMDR.

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data through the REST API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.9.0**.

## Setup

### To collect data through REST API, follow the below steps:

- Considering you already have a Qualys user account, to identify your Qualys platform and get the API URL, refer this [link](https://www.qualys.com/platform-identification/).
- Alternative way to get the API URL is to log in to your Qualys account and go to Help > About. You’ll find your URL under Security Operations Center (SOC).

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type Qualys VMDR
3. Click on the "Qualys VMDR" integration from the search results.
4. Click on the Add Qualys VMDR Integration button to add the integration.
5. While adding the integration, if you want to collect Asset Host Detection data via REST API, then you have to put the following details:
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

**NOTE**: By default, the input parameter is set to "action=list".

## Data reference

### Asset Host Detection

This is the `Asset Host Detection` dataset.

#### Example

{{event "asset_host_detection"}}

{{fields "asset_host_detection"}}

### Knowledge Base

This is the `Knowledge Base` dataset.

#### Example

{{event "knowledge_base"}}

{{fields "knowledge_base"}}

### User Activity

This is the `User Activity` dataset. It connects to an [API](
https://docs.qualys.com/en/vm/api/users/index.htm#t=activity%2Fexport_activity.htm)
that exports the user activity log. 

#### Example

{{event "user_activity"}}

{{fields "user_activity"}}