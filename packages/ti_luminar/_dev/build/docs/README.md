# Luminar Intelligence integration

This integration connects with the [Luminar Threat Intelligence](https://www.cognyte.com/) TAXII version 2 server.
It includes the following datasets for retrieving logs:

| Dataset | Luminar Collection name |
|--------:|:-----------------------|
|     ioc | IOCs                   |
|  leakedrecords | Leaked Records  |
|      cyberfeeds | Cyber Feeds    |

## Expiration of Indicators of Compromise (IOCs)
The ingested IOCs expire after certain duration. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for every source index to 
facilitate only active IOCs be available to the end users. Each transform creates a destination index named `logs-ti_luminar_latest.*` which only contains active and unexpired IOCs.
Destinations indices are aliased to `logs-ti_luminar_latest.<feed name>`.

| Source Datastream        | Destination Index Pattern          | Destination Alias           |
|:-------------------------|:-----------------------------------|-----------------------------|
| `logs-ti_luminar.iocs-*`     | logs-ti_luminar_latest.iocs-*     | logs-ti_luminar_latest.iocs     |
| `logs-ti_luminar.leakedrecords-*`  | logs-ti_luminar_latest.leakedrecords-*  | logs-ti_luminar_latest.leakedrecords  |
| `logs-ti_luminar.cyberfeeds-*`      |  logs-ti_luminar_latest.cyberfeeds-*      | logs-ti_luminar_latest.cyberfeeds      |

### ILM Policy
ILM policy is added to the source indices, so it doesn't lead to unbounded growth.
Data in these source indices will be deleted after a certain number of days from ingested days:

|                  Index | Deleted after |
|-----------------------:|:--------------|
|     `logs-ti_luminar.iocs-default_policy` | 5d          |
|  `logs-ti_luminar.leakedrecords-default_policy` | 5d            |
|      `logs-ti_luminar.cyberfeeds-default_policy` | 5d            |

## Requirements

Elastic Agent must be installed.
For more information,
refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure,
and manage your agents in a central location.
We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach,
you install Elastic Agent and manually configure the agent locally on the system where it’s installed.
You are responsible for managing and upgrading the agents.
This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone.
Docker images for all versions of Elastic Agent are available from the Elastic Docker registry,
and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information,
refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

## Setup

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type Luminar Threat Intelligence.
3. Click on the "Luminar Threat Intelligence" integration from the search results.
4. Click on the "Add Luminar Threat Intelligence" button to add the integration.
5. Configure all required integration parameters, including accountId, clientId, clientSecret that you have received from Luminar during onboarding process. For more information, please visit [Luminar Threat Intelligence](https://www.cognyte.com/) page.
6. Enable data streams you are interested in and have access to.
7. Save the integration.

## Logs

### IOCs

{{fields "iocs"}}

{{event "iocs"}}

### Leaked Records

{{fields "leakedrecords"}}

{{event "leakedrecords"}}

### Cyber Feeds

{{fields "cyberfeeds"}}

{{event "cyberfeeds"}}