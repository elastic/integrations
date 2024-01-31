# SpyCloud

This [SpyCloud](https://spycloud.com/) integration is the market leader in protecting enterprises and their customers from online fraud, account takeover, and follow-on attacks like ransomware. It offers unique data richness and transparency that goes beyond just finding compromised credentials. We provide an early warning of compromised credentials and malware-infected users, so you can take action before the criminals do.

The SpyCloud integration uses REST API mode to collect data. Elastic Agent fetches data via API endpoints.

## Compatibility

This module has been tested against the latest SpyCloud version **v2**.

## Data streams

The SpyCloud integration collects three types of logs: Breach Catalog, Breach Record and Compass.

**[Breach Catalog](https://spycloud-external.readme.io/sc-enterprise-api/reference/catalog-list)** - SpyCloud maintains a catalog of thousands of breaches which allows it to search for different breaches in the network.

**[Breach Record](https://spycloud-external.readme.io/sc-enterprise-api/reference/data-watchlist)** - SpyCloud maintains their own watchlist.

**[Compass](https://spycloud-external.readme.io/sc-enterprise-api/reference/compass-data-get)** - Compass gives enterprises full visibility into a malware infection including compromised assets like exposed credentials and authentication cookies that lead to future ransomware attacks.

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

The minimum **kibana.version** required is **8.11.0**.

## Setup

### To collect logs through REST API, follow the below steps:

- Considering you already have a SpyCloud account, log in to your SpyCloud instance to obtain your API key. Navigate to Main > API, where you will find your API key under the Keys > API Key section.
- To obtain the Base URL, navigate to Main > API and click on the "View Docs" link, your URL can be located within the API Reference section.

**NOTE**: Your system's IP should be whitelisted by the SpyCloud team to be able to access the APIs and get the data.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type SpyCloud.
3. Click on the "SpyCloud" integration from the search results.
4. Click on the Add SpyCloud Integration button to add the integration.
5. While adding the integration, if you want to collect Breach Catalog logs via REST API, please enter the following details:
   - URL
   - API Key
   - Interval

   or if you want to collect Breach Record logs via REST API, please enter the following details:
   - URL
   - API Key
   - Initial Interval
   - Interval
   - Severity

   or if you want to collect Compass logs via REST API, please enter the following details:
   - URL
   - API Key
   - Initial Interval
   - Interval

**NOTE**: By default, the URL is set to "https://api.spycloud.io/enterprise-v2".

## Logs Reference

### Breach Catalog

This is the `Breach Catalog` dataset.

#### Example

{{event "breach_catalog"}}

{{fields "breach_catalog"}}

### Breach Record

This is the `Breach Record` dataset.

#### Example

{{event "breach_record"}}

{{fields "breach_record"}}

### Compass

This is the `Compass` dataset.

#### Example

{{event "compass"}}

{{fields "compass"}}