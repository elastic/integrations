# Prisma Cloud

This [Prisma Cloud](https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin-compute/welcome) is a cloud infrastructure security solution and a Security Operations Center (SOC) enablement tool that enables you to address risks and secure your workloads in a heterogeneous environment (hybrid and multi cloud) from a single console. It provides complete visibility and control over risks within your public cloud infrastructure—Amazon Web Services (AWS), Microsoft Azure, Google Cloud Platform (GCP), Oracle Cloud Infrastructure (OCI), Alibaba Cloud— and enables you to manage vulnerabilities, detect anomalies, ensure compliance, and provide runtime defense in heterogeneous environments, such as Windows, Linux, Kubernetes, Red Hat OpenShift, AWS Lambda, Azure Functions, and GCP Cloud Functions.

## Prisma Cloud Security Posture Management (CSPM)

Single pane of glass for both CSPM (Cloud Security Posture Management) & CWPP (Cloud Workload Protection Platform). Compute (formerly Twistlock, a CWPP solution) is delivered as part of the larger Prisma Cloud system. Palo Alto Networks runs, manages, and updates Compute Console for you. You deploy and manage Defenders in your environment. You access the Compute Console from a tab within the Prisma Cloud user interface.

CSPM uses REST API mode to collect data. Elastic Agent fetches data via API endpoints.

## Prisma Cloud Workload Protection (CWP)

Self-hosted, stand-alone, self-operated version of Compute (formerly Twistlock). Download the entire software suite, and run it in any environment. You deploy and manage both Console and Defenders.

CWP can be used in two different modes to collect data:
- REST API mode.
- Syslog mode: This includes TCP and UDP.

## Compatibility

This module has been tested against the latest CSPM version **v2** and CWP version **v30.03**.

## Data streams

The Prisma Cloud integration collects data for the following event types:

| Event Type                    |
|-------------------------------|
| Alert                         |
| Audit                         |
| Host                          |
| Host Profile                  |
| Incident Audit                |

**NOTE**:

Alert and Audit data-streams are part of [CSPM](https://pan.dev/prisma-cloud/api/cspm/) module, whereas Host, Host Profile and Incident Audit are part of [CWP](https://pan.dev/prisma-cloud/api/cwpp/) module.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Agentless-enabled integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Setup

### To collect data through REST API, follow these steps"

### CSPM

1. Assuming that you already have a Prisma Cloud account, to obtain an access key ID and secret access key from the Prisma Cloud system administrator, check [how to create access keys](https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin/manage-prisma-cloud-administrators/create-access-keys).
2. The base URL of your CSPM API request depends on the region of your Prisma Cloud tenant and is similar to your Prisma Cloud administrative console URL. Check your URL from the [API URLs](https://pan.dev/prisma-cloud/api/cspm/api-urls/).

### CWP

1. Assuming that you've already generated your access key ID and secret access key from the Prisma Cloud Console; if not, check the CSPM section. The base URL of your CWP API request depends on the console path and the API version of your Prisma Cloud Compute console.
3. To find your API version, log in to your Prisma Cloud Compute console and click the bell icon in the top right of the page.
4. To get your console path, navigate to **Compute** > **Manage** > **System** > **Downloads**. Your console path is listed under **Path to Console**.
5. Create your base URL in this format: `https://<CONSOLE>/api/v<VERSION>`.

**NOTE**: You can specify a date and time for the access key validity. If you do not select key expiry, the key is set to never expire; if you select it, but do not specify a date, the key expires in a month.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **Palo Alto Prisma Cloud**.
3. Select the **Palo Alto Prisma Cloud** integration and add it.
4. While adding the integration, if you want to collect Alert and Audit data via REST API, then you have to put the following details:
   - username
   - password
   - url
   - interval
   - time amount
   - time unit
   - batch size

   or if you want to collect Host, Host Profile and Incident Audit data via REST API, then you have to put the following details:
   - username
   - password
   - url
   - interval
   - offset
   - batch size

  or if you want to collect Host, Host Profile and Incident Audit data via TCP/UDP, then you have to put the following details:
   - listen address
   - listen port

**NOTE**: Your Access key ID is your username and the Secret Access key is your password.

## Logs Reference

### Alert

This is the `Alert` dataset.

#### Example

{{event "alert"}}

{{fields "alert"}}

### Audit

This is the `Audit` dataset.

#### Example

{{event "audit"}}

{{fields "audit"}}

### Host

This is the `Host` dataset.

#### Example

{{event "host"}}

{{fields "host"}}

### Host Profile

This is the `Host Profile` dataset.

#### Example

{{event "host_profile"}}

{{fields "host_profile"}}

### Incident Audit

This is the `Incident Audit` dataset.

#### Example

{{event "incident_audit"}}

{{fields "incident_audit"}}