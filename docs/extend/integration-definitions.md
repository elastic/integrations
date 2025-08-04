---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/integration-definitions.html
---

# Definitions [integration-definitions]


## Package [_package]

An Elastic Package, or simply package for short, contains the dashboards, visualisations, and configurations to monitor the logs and metrics of a particular technology or group of related services, such as “MySQL”, or “System”.

The package consists of:

* Name
* Zero or more dashboards and visualisations and Canvas workpads
* Zero or more ML job definitions
* Zero or more data stream index templates

The package is versioned.


## Integration [_integration]

An integration is a specific type of a package defining data streams used to observe a product using logs, metrics, and traces.


## Content Package [_content_package]

A content package is a type of package that contains only Kibana assets without any data collection configuration. These packages are used to provide pre-built dashboards, visualizations, Canvas workpads, and saved searches that work with existing data.

Unlike integrations, content packages do not include data streams or Agent policy templates, as they don't collect data themselves.


## Data stream [_data_stream]

A data stream is logical sub-division of an Integration package, dealing with a specific type of observable aspect of the service or product being observed. For example, the `mysql` package defines a data stream for collecting metrics and another data stream for collecting server logs.

A data stream defines all the assets needed to create an Elasticsearch data stream, for example: index templates and ingest pipelines. These assets are loaded into Elasticsearch when a user installs a package via the Fleet UI in Kibana.

A data stream also defines a policy template. Policy templates include variables that allow users to configure the data stream via the Fleet UI in Kibana. The resulting policy is interpreted by the Elastic Agent to collect relevant information from the product or service being observed.

Data streams are defined inside the `data_stream` folder located under the package’s root directory. Each data stream is defined in it’s own sub-folder.

The data stream consists of:

* Field definitions (`fields.yml` files)
* Zero or more [ingest pipelines](https://www.elastic.co/docs/manage-data/ingest/transform-enrich/ingest-pipelines)
* An Elastic Agent policy template


## Package Manifest [_package_manifest]

The package manifest (`manifest.yml`) is the main configuration file that defines a package's metadata and structure. Located at the root of every package, it contains:

* Package name, version, and description
* Format version (package-spec compatibility)
* License information
* Categories and tags for classification
* Minimum Kibana versions required
* Policy templates that define configurable inputs
* Owner information for maintenance

The manifest is essential for package discovery, installation, and configuration through Fleet.


## Input [_input]

An input is a component that defines how Elastic Agent collects data from a specific source. Each input type corresponds to a different data collection method. 

Inputs are configured within policy templates in the package manifest and can include variables that users configure through the Fleet UI. Each data stream typically uses one or more inputs to collect its data.


## Agent Policy [_agent_policy]

An Agent Policy is a configuration that defines what data should be collected and how to collect it. There are two deployment modes:

### Agent-based deployments
In traditional deployments, agent policies are deployed to one or more Elastic Agents installed on hosts. The policy includes:
* One or more integrations with their specific configurations
* Output settings (where to send the data)
* Agent monitoring settings
* Download source for agent upgrades

A single agent can only have one policy at a time, but a policy can be assigned to multiple agents.

### Agentless deployments
For agentless integrations, Elastic manages the infrastructure and runs Elastic
Agent on behalf of the user. In this mode:
* No agent installation is required on user infrastructure
* Elastic automatically provisions and scales the necessary resources
* Configuration is still done through Fleet UI, but deployment is handled by Elastic
* Particularly useful for cloud service integrations (AWS, Azure, GCP) where API access is sufficient

Agentless is available for select integrations and requires specific licensing.

## Development Extensions: `_dev` directories [_development_extensions_dev_directories]

The `_dev` directory is part of the [package-spec](https://github.com/elastic/package-spec), and contains development resources. These development resources cover any types of files or folders needed only at development time. This includes resources needed for testing, but also includes any templates that might be used for generating documentation. In the future it could include other files or folders needed just at development time. It can be defined on the following levels:

1. The package-level `_dev` folder contains files needed to set up the testing environment for that package. This environment setup is specified by files and folders in the `_dev/deploy` folder. For example, the `apache` package [specifies](https://github.com/elastic/integrations/tree/main/packages/apache/_dev/deploy) how to spin up an Apache Docker container for testing.
2. The data stream-level `_dev` folder contains test configuration files for various types of tests. For example, see the [`_dev/test folder`](https://github.com/elastic/integrations/tree/main/packages/apache/data_stream/error/_dev/test) under the `apache/error` data stream. The integrations have also [asset](https://github.com/elastic/elastic-package/blob/main/docs/howto/asset_testing.md) and [static](https://github.com/elastic/elastic-package/blob/main/docs/howto/static_testing.md) tests. They don’t require config files, but configs can be used to mark them as optional.

