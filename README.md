[![Build status](https://badge.buildkite.com/153e2f7f984d3b1b350d8cb5d2fe7e7ae924982d5bd5b5ee49.svg?branch=main)](https://buildkite.com/elastic/integrations)

# Elastic Integrations

This repository contains sources for Elastic Integrations. Each Elastic Integration is an Elastic Package that defines how to observe a specific product with the Elastic Stack.

An Elastic Package may define configuration for the [Elastic Agent](#elastic-agent) as well as assets (such as Kibana dashboards and Elasticsearch index templates) for the Elastic Stack. It should also define documentation about the package. Finally, a package may also define tests to ensure that it is functioning as expected.

Elastic Packages have a certain, well-defined structure. This structure is described by the [Package Specification](#package-specification). The repository is also used for discussions about extending the specification (with proposals).

While this repository contains _sources_ for Elastic Integrations, _built_ Elastic Integrations are published into a storage based on Google Cloud bucket (more info [here](https://github.com/elastic/elastic-package/blob/85d6fcacad736e543e459a044a5e0fa48b5d43c6/docs/howto/use_package_storage_v2.md)) and served up via the [Package Registry](#package-registry). The Fleet UI in Kibana connects to the Package Registry and allows users to discover, install, and configure Elastic Packages.

## Contributing

Please review the [Contributing Guide](CONTRIBUTING.md) to learn how to build and develop packages, understand the release procedure and
explore the builder tools.

 More information about the CI pipelines that are available in this repostiory [here](./docs/ci_pipelines.md).

## External links

### Package Specification
* [Repository](https://github.com/elastic/package-spec)
* [Explore the package specification](https://github.com/elastic/package-spec/tree/main/spec)
* [Suggest changes to the package specification](https://github.com/elastic/package-spec/issues/new)
  repository. Let's discuss any spec extensions together

### Elastic Package
* [Repository](https://github.com/elastic/elastic-package)
* [Changelog of the `elastic-package` releases](https://github.com/elastic/elastic-package/releases)

### Package Registry
* [Repository](https://github.com/elastic/package-registry)
* [Release latest changes introduced to the Package Registry](https://github.com/elastic/package-registry/#release)

### Elastic Agent
* [Repository](https://github.com/elastic/elastic-agent/tree/main)

## Test Coverage

[![Test Coverage Report](https://fleet-ci.elastic.co/job/ingest-manager/job/integrations/job/main/cobertura/graph)](https://fleet-ci.elastic.co/job/Ingest-manager/job/integrations/job/main/cobertura/)
