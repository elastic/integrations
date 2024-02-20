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

The Prisma Cloud integration collects data for the following five events:

| Event Type                    |
|-------------------------------|
| Alert                         |
| Audit                         |
| Host                          |
| Host Profile                  |
| Incident Audit                |

**NOTE**:

1. Alert and Audit data-streams are part of [CSPM](https://pan.dev/prisma-cloud/api/cspm/) module, whereas Host, Host Profile and Incident Audit are part of [CWP](https://pan.dev/prisma-cloud/api/cwpp/) module.
2. Currently, we are unable to collect logs of Incident Audit datastream via defined API. Hence, we have not added the configuration of Incident Audit data stream via REST API.

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

The minimum **kibana.version** required is **8.10.1**.

## Setup

### To collect data through REST API, follow the below steps:

### CSPM

1. Considering you already have a Prisma Cloud account, to obtain an access key ID and secret access key from the Prisma Cloud system administrator, refer this [link](https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin/manage-prisma-cloud-administrators/create-access-keys).
2. The base URL of your CSPM API request depends on the region of your Prisma Cloud tenant and is similar to your Prisma Cloud administrative console URL. Obtain your URL from this [link](https://pan.dev/prisma-cloud/api/cspm/api-urls/).

### CWP

1. Assuming you've already generated your access key ID and secret access key from the Prisma Cloud Console; if not, see the section above.
2. The base URL of your CWP API request depends on the console path and the API version of your Prisma Cloud Compute console.
3. To find your API version, log in to your Prisma Cloud Compute console, click the bell icon in the top right of the page, your API version is displayed.
4. To get your console path, navigate to Compute > Manage > System > Downloads. you can find your console path listed under Path to Console.
5. Now you can create your base URL in this format: `https://<CONSOLE>/api/v<VERSION>`.

**NOTE**: You can specify a date and time for the access key validity. If you do not select key expiry, the key is set to never expire; if you select it, but do not specify a date, the key expires in a month.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type Palo Alto Prisma Cloud.
3. Click on the "Palo Alto Prisma Cloud" integration from the search results.
4. Click on the Add Palo Alto Prisma Cloud Integration button to add the integration.
5. While adding the integration, if you want to collect Alert and Audit data via REST API, then you have to put the following details:
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

**NOTE**: Your Access key ID is your username and Secret Access key is your password.

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