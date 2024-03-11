# ESET Threat Intelligence Integration

This integration connects with the [ESET Threat Intelligence](https://eti.eset.com/taxii2/) TAXII version 2 server.
It includes the following datasets for retrieving logs:

| Dataset | TAXII2 Collection name |
|--------:|:-----------------------|
|     apt | apt stix 2.1           |
|  botnet | botnet stix 2.1        |
|      cc | botnet.cc stix 2.1     |
| domains | domain stix 2.1        |
|   files | file stix 2.1          |
|      ip | ip stix 2.1            |
|     url | url stix 2.1           |

## Expiration of Indicators of Compromise (IOCs)
The ingested IOCs expire after certain duration. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for every source index to 
facilitate only active IOCs be available to the end users. Each transform creates a destination index named `logs-ti_eset_latest.dest_*` which only contains active and unexpired IOCs.
Destinations indices are aliased to `logs-ti_eset_latest.<feed name>`.

| Source Datastream        | Destination Index Pattern          | Destination Alias           |
|:-------------------------|:-----------------------------------|-----------------------------|
| `logs-ti_eset.apt-*`     | logs-ti_eset_latest.dest_apt-*     | logs-ti_eset_latest.apt     |
| `logs-ti_eset.botnet-*`  | logs-ti_eset_latest.dest_botnet-*  | logs-ti_eset_latest.botnet  |
| `logs-ti_eset.cc-*`      | logs-ti_eset_latest.dest_cc-*      | logs-ti_eset_latest.cc      |
| `logs-ti_eset.domains-*` | logs-ti_eset_latest.dest_domains-* | logs-ti_eset_latest.domains |
| `logs-ti_eset.files-*`   | logs-ti_eset_latest.dest_files-*   | logs-ti_eset_latest.files   |
| `logs-ti_eset.ip-*`      | logs-ti_eset_latest.dest_ip-*      | logs-ti_eset_latest.ip      |
| `logs-ti_eset.url-*`     | logs-ti_eset_latest.dest_url-*     | logs-ti_eset_latest.url     |

### ILM Policy
ILM policy is added to the source indices, so it doesn't lead to unbounded growth.
Data in these source indices will be deleted after a certain number of days from ingested days:

|                  Index | Deleted after | Expired after |
|-----------------------:|:--------------|---------------|
|     `logs-ti_eset.apt` | 365d          | 365d          |
|  `logs-ti_eset.botnet` | 7d            | 48h           |
|      `logs-ti_eset.cc` | 7d            | 48h           |
| `logs-ti_eset.domains` | 7d            | 48h           |
|   `logs-ti_eset.files` | 7d            | 48h           |
|      `logs-ti_eset.ip` | 7d            | 48h           |
|     `logs-ti_eset.url` | 7d            | 48h           |

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

The minimum **Kibana version** required is **8.12.0**.

## Setup

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type ESET Threat Intelligence.
3. Click on the "ESET Threat Intelligence" integration from the search results.
4. Click on the "Add ESET Threat Intelligence" button to add the integration.
5. Configure all required integration parameters, including username and password that you have received from ESET during onboarding process. For more information, please visit [ESET Threat Intelligence](https://www.eset.com/int/business/services/threat-intelligence/) page.
6. Enable data streams you are interested in and have access to.
7. Save the integration.

## Logs

### Botnet

{{fields "botnet"}}

{{event "botnet"}}

### C&C

{{fields "cc"}}

{{event "cc"}}

### Domains

{{fields "domains"}}

{{event "domains"}}

### Malicious files

{{fields "files"}}

{{event "files"}}

### IP

{{fields "ip"}}

{{event "ip"}}

### APT

{{fields "apt"}}

{{event "apt"}}

### URL

{{fields "url"}}

{{event "url"}}