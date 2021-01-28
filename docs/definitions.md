# Definitions

## Package

A package contains the dashboards, visualisations, and configurations to monitor the logs and metrics of a particular technology or group of related services, such as “MySQL”, or “System”.

The package consists of:

* Name
* Zero or more dashboards and visualisations and Canvas workpads
* Zero or more ML job definitions
* Zero or more data stream templates

The package is versioned.

## Integration

An integration is a specific type of a _package_ defining data streams used to observe a product using logs, metrics, and traces.

## Data stream

A data stream is part of a package and contains all the assets which are needed to create a data stream. Example for assets are: ingest pipeline, agent policy template, ES index template, ...

Data streams are inside the package directory under `data stream`.

The data stream consists of:

* An alias templates (or the fields.yml to create it)
* Zero or more ingest pipelines
* An Elastic Agent policy template

## Migration from Beats

A defined importing procedure used to transform both Filebeat and Metricbeat modules, related to
the same observed product, into a single integration. The integration contains extracted configuration of beat
modules, hence no modules are required to exist anymore.
