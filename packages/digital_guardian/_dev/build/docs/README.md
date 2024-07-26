# Digital Guardian

This integration is for [Digital Guardian logs](https://www.digitalguardian.com/). 

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

This module has been tested against the **Digital Guardian API version v1**.


## To collect data from Digital Guardian ARC API, follow the below steps:

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type Digital Guardian.
3. Click on the "Digital Guardian" integration from the search results.
4. Click on the "Add Digital Guardian" button to add the integration.
5. Configure all required integration parameters, including URL, Client ID, Client Secret, Scope, Token URL, Export Profile, to enable data collection for Digital Guardian ARC API.
6. Save the integration.

## Logs reference

### arc

This is the `arc` dataset.

#### Example

{{event "arc"}}

{{fields "arc"}}
