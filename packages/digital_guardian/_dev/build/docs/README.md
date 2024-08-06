# Digital Guardian

This integration is for ingesting events and alerts from [Fortra's Digital Guardian](https://www.digitalguardian.com/). Fortra’s Digital Guardian helps organizations protect data, performing across the corporate network, traditional endpoints, and cloud applications. Digital Guardian's data loss prevention, available as a software-as-a-service or managed service, helps to see that data, support compliance initiatives, and protect against serious risk. 

The integration allows collection of events and alerts from [Digital Guardian Analytics & Reporting Cloud (ARC)](https://www.digitalguardian.com/blog/new-dawn-dlp-digital-guardian-releases-its-analytics-reporting-cloud-arc) via the REST API.

## Data streams

The Digital Guardian integration collects events to populate following data-streams:

- `digital_guardian.arc`: Collects all events and alerts from `Digital Guardian Analytics & Reporting Cloud (ARC)` via the REST API.

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

## Setup

### Digital Guardian ARC

#### Copy Digital Guardian ARC required configuration properties:

1. Copy `Client ID`: From ARC Tenant Settings, copy the Tenant ID.
2. Copy `Client Secret`: From ARC Tenant Settings, copy the Authentication Token.
3. Copy `ARC Server URL`: From Digital Guardian Management Console (DGMC), copy the Access Gateway Base URL.
4. Copy `Authorization Server URL`: From Digital Guardian Management Console (DGMC), copy the Authorization server URL.
5. Copy `ARC Export Profile ID`: 
    - Navigate to `Admin > reports > export profiles`
    - Copy only the GUID part from the export profile.

#### Enabling the Digital Guardian integration in Elastic with ARC dataset:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type Digital Guardian.
3. Click on the "Digital Guardian" integration from the search results.
4. Click on the "Add Digital Guardian" button to add the integration.
5. Configure all required integration parameters. 
    - ARC data requires following parameters:
        - `Client ID`
        - `Client Secret`
        - `ARC Server URL`
        - `Authorization Server URL`
        - `ARC Export Profile ID`
6. Save the integration.

## Logs reference

### arc

This is the `arc` dataset.

#### Example

{{event "arc"}}

{{fields "arc"}}
