[![Build Status](https://beats-ci.elastic.co/job/ingest-manager/job/integrations/job/main/badge/icon)](https://beats-ci.elastic.co/job/ingest-manager/job/integrations/job/main/)

# Elastic Integrations

This repository contains sources for Elastic Integrations. Each Elastic Integration is an Elastic Package that defines how to observe a specific product with the Elastic Stack.

An Elastic Package may define configuration for the [Elastic Agent](#elastic-agent) as well as assets (such as Kibana dashboards and Elasticsearch index templates) for the Elastic Stack. It should also define documentation about the package. Finally, a package may also define tests to ensure that it is functioning as expected.

Elastic Packages have a certain, well-defined structure. This structure is described by the [Package Specification](#package-spec). The repository is also used for discussions about extending the specification (with proposals).

While this repository contains _sources_ for Elastic Integrations, _built_ Elastic Integrations are stored in the [Package Storage](#package-storage) repository and served up via the [Package Registry](#package-registry). The Fleet UI in Kibana connects to the Package Registry and allows users to discover, install, and configure Elastic Packages.

## Contributing

Please review the [Contributing Guide](CONTRIBUTING.md) to learn how to build and develop packages, understand the release procedure and
explore the builder tools.

## External links

### Package Specification
* [Repository](https://github.com/elastic/package-spec)
* [Explore the current version of the package specification](https://github.com/elastic/package-spec/tree/master/versions/1)
* [Suggest changes to the package specification](https://github.com/elastic/package-spec/issues/new)
  repository. Let's discuss any spec extensions together

### Package Registry
* [Repository](https://github.com/elastic/package-registry)
* [Release latest changes introduced to the Package Registry](https://github.com/elastic/package-registry/#release)

### Package Storage
* [Repository](https://github.com/elastic/package-storage)
* [Update Docker images of Package Storage to include latest release of the Package Registry](https://github.com/elastic/package-storage#update-package-registry-for-a-distribution)

### Elastic Agent
* [Repository](https://github.com/elastic/beats/tree/master/x-pack/elastic-agent)

## Test Coverage

[![Test Coverage Report](https://beats-ci.elastic.co/job/ingest-manager/job/integrations/job/main/cobertura/graph)](https://beats-ci.elastic.co/job/Ingest-manager/job/integrations/job/main/cobertura/)
