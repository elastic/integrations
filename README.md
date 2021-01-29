[![Build Status](https://beats-ci.elastic.co/job/ingest-manager/job/integrations/job/master/badge/icon)](https://beats-ci.elastic.co/job/ingest-manager/job/integrations/job/master/)

# Elastic Integrations

This repository contains sources for Elastic Integrations. Each Elastic Integration is an Elastic Package that defines how to observe a specific product with the Elastic Stack.

An Elastic Package may define configuration for the [Elastic Agent](https://github.com/elastic/beats/tree/master/x-pack/elastic-agent) as well as assets (such as Kibana dashboards and Elasticsearch index templates) for the Elastic Stack. It should also define documentation about the package. Finally, a package may also define tests to ensure that it is functioning as expected.

Elastic Packages have a certain, well-defined structure. This structure is described by the [Package Specification](https://github.com/elastic/package-spec). The repository is also used for discussions about extending the specification (with proposals).

While this repository contains _sources_ for Elastic Integrations, _built_ Elastic Integrations are stored in the [Package Storage](https://github.com/elastic/package-storage) repository and served up via the [Package Registry](https://github.com/elastic/package-registry/). The Fleet UI in Kibana connects to the Package Registry and allows users to discover, install, and configure Elastic Packages.

## Contributing

Please review the [Contributing Guide](CONTRIBUTING.md) to learn how to build and develop packages, understand the release procedure and
explore the builder tools.

## External links

### Package Specification
* [Explore the current version of the package specification](https://github.com/elastic/package-spec/tree/master/versions/1)
* [Suggest changes to the package specification](https://github.com/elastic/package-spec/issues/new)
  repository. Let's discuss any spec extensions together

### Package Registry
* [Create a new release](https://github.com/elastic/package-registry/#release) - release latest changes introduced to the [Package Registry](https://github.com/elastic/package-registry)

### Package Storage
* [Update Package-Registry for a distribution](https://github.com/elastic/package-storage#update-package-registry-for-a-distribution) - update Docker images 
  of Package Storage to include latest release of the Package Registry](https://github.com/elastic/package-storage#update-package-registry-for-a-distribution)
