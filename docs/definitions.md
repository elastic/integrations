# Definitions

## Package

An Elastic Package, or simply package for short, contains the dashboards, visualisations, and configurations to monitor the logs and metrics of a particular technology or group of related services, such as “MySQL”, or “System”.

The package consists of:

* Name
* Zero or more dashboards and visualisations and Canvas workpads
* Zero or more ML job definitions
* Zero or more data stream index templates

The package is versioned.

## Integration

An integration is a specific type of a _package_ defining data streams used to observe a product using logs, metrics, and traces.

## Data stream

A data stream is logical sub-division of an Integration package, dealing with a specific type of observable aspect of the service or product being observed. For example, the `mysql` package defines a data stream for collecting metrics and another data stream for collecting server logs.

A data stream defines all the assets needed to create an Elasticsearch data stream, for example: index templates and ingest pipelines. These assets are loaded into Elasticsearch when a user installs a package via the Fleet UI in Kibana.

A data stream also defines a policy template. Policy templates include variables that allow users to configure the data stream via the Fleet UI in Kibana. The resulting policy is interpreted by the Elastic Agent to collect relevant information from the product or service being observed.

Data streams are defined inside the `data_stream` folder located under the package's root directory. Each data stream is defined in it's own sub-folder.

The data stream consists of:

* Field definitions (`fields.yml` files)
* Zero or more ingest pipelines
* An Elastic Agent policy template

## Development Extensions: '_dev' directories

The `_dev` directory is part of [the package spec](https://github.com/elastic/package-spec), containing development resources. These development resources cover any types of files/folders needed only at development time. This includes resources needed for testing but also includes any templates that might be used for generating documentation. In the future it could include other files/folders needed just at development time. It can be defined on the following levels:

1. the package-level `_dev` folder contains files needed to setup the testing environment for that package. This environment setup is specified via folders/files in the `_dev/deploy` folder. For example, the `apache` package [specifies](https://github.com/elastic/integrations/tree/main/packages/apache/_dev/deploy) how to spin up an Apache Docker container for testing.
1. the data stream-level `_dev` folder contains test configuration files for various types of tests. For example, see the [`_dev/test` folder](https://github.com/elastic/integrations/tree/main/packages/apache/data_stream/error/_dev/test) under the `apache/error` data stream.

The integrations have also [asset](https://github.com/elastic/elastic-package/blob/main/docs/howto/asset_testing.md) and [static](https://github.com/elastic/elastic-package/blob/main/docs/howto/static_testing.md) tests. They don't require config files, but configs can be used to mark them as optional.

## Migration from Beats Modules

Filebeat and Metricbeat modules can be migrated over to Elastic Integrations. When migrating over, the same module in Filebeat and Metricbeat, related to the same observed product, can be combined into a single Elastic Integration.

[Learn more](/docs/import_from_beats.md) about how to migrate Filebeat and Metricbeat modules to Elastic Integrations.
