# SpyCloud Enterprise Protection

## Ingest SpyCloud Cybercrime Analytics into Elastic Agent

[SpyCloud’s Enterprise Protection](https://spycloud.com/) integration leverages recaptured darknet data to safeguard employees' digital identities by producing actionable insights to proactively prevent account takeover and follow-on targeted attacks before they happen.

The Elastic Agent uses the SpyCloud Enterprise Protection REST API to collect data.

## Compatibility

This module has been tested against the latest SpyCloud Enterprise Protection API **V2**.

## Data streams

The SpyCloud integration collects three types of logs: Breach Catalog, Breach Record and Compass Malware Records.

- **[Breach Catalog](https://spycloud-external.readme.io/sc-enterprise-api/reference/catalog-list)** - a collection of third-party breach and malware data ingested into SpyCloud. The catalog contains thousands of breach objects, each of which contain metadata for a particular breach. A typical breach object contains a variety of metadata including a breach title, description, acquisition date, link to affected websites and many more data points.

- **[Breach Record](https://spycloud-external.readme.io/sc-enterprise-api/reference/data-watchlist)** - a collection of data assets extracted from third-party breach and malware data. These assets are grouped together to form a data record which represents a single user account or individual persona in parsed data.

- **[Compass Malware Records](https://spycloud-external.readme.io/sc-enterprise-api/reference/compass-data-get)** - a collection of data assets extracted from malware data that provides full visibility into infection events to enable post-infection remediation on compromised devices, users, and applications.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

### Collect logs through REST API

1. Considering you already have a SpyCloud account, log in to your SpyCloud instance to obtain your API key. Navigate to **Main > API**, where you will find your API key under the **Keys > API Key** section.
2. To obtain the Base URL, navigate to **Main > API** and click on the **View Docs** link, your URL can be located within the **API Reference** section.

**NOTE**: Your system's IP should be allowlisted by the SpyCloud team to be able to access the APIs and get the data.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **SpyCloud Enterprise Protection**.
3. Select the **SpyCloud Enterprise Protection** integration and add it.
4. While adding the integration, if you want to collect Breach Catalog logs via REST API, please enter the following details:
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
5. Save the integration.

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
