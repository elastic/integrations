# Symantec EDR Cloud

Symantec Endpoint Security is the fully cloud-managed version of the on-premises Symantec Endpoint Protection (SEP), which delivers multilayer protection to stop threats regardless of how they attack your endpoints. You manage Symantec Endpoint Security through a unified cloud console that provides threat visibility across your endpoints and uses multiple technologies to manage the security of your organization.

## Data streams

This integration supports ingestion of incidents from Symantec EDR Cloud, via the [Incidents API](https://apidocs.securitycloud.symantec.com/#/doc?id=edr_incidents).

**Incident** is used to retrieve EDR incidents. See more details in the API documentation [here](https://apidocs.securitycloud.symantec.com/#/doc?id=edr_incidents).

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

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

This module has been tested against the **Symantec EDR Cloud API Version v1**.

## Setup

### To collect data from Symantec EDR Cloud, the following parameters from your Symantec EDR Cloud instance are required:

1. Client ID
2. Client Secret

### Steps to obtain Client ID and Client Secret:

1. Login to your [Symantec EDR Cloud console](https://sep.securitycloud.symantec.com/v2/landing).
2. Click Integration > Client Applications.
3. Click Add for adding Client Application.
4. Enter Client Application Name and press the Add button.
5. Select Client Secret from the top.
6. Copy the Client ID and Client Secret.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type Symantec EDR Cloud
3. Click on the "Symantec EDR Cloud" integration from the search results.
4. Click on the "Add Symantec EDR Cloud" button to add the integration.
5. Add all the required integration configuration parameters, such as Client ID, Client Secret, URL, and Token URL. For incident data stream, these parameters must be provided in order to retrieve logs.
6. Save the integration.

### Troubleshooting

If the user stops integration and starts integration again after 30 days, then user will not be able to collect data and will get an error as Symantec EDR Cloud only collects data for the last 30 days. To avoid this issue, create a new integration instead of restarting it after 30 days.

## Logs Reference

### Incident

This is the `Incident` dataset.

#### Example

{{event "incident"}}

{{fields "incident"}}
