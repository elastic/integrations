[![Build Status](https://beats-ci.elastic.co/job/ingest-manager/job/integrations/job/master/badge/icon)](https://beats-ci.elastic.co/job/ingest-manager/job/integrations/job/master/)

# Elastic Integrations

This repository contains sources for Elastic Integrations. Each Elastic Integration is an Elastic Package that defines how to observe a specific product with the Elastic Stack.

An Elastic Package may define configuration for the [Elastic Agent](https://github.com/elastic/beats/tree/master/x-pack/elastic-agent) as well as assets (such as Kibana dashboards and Elasticsearch index templates) for the Elastic Stack. It should also define documentation about the package. Finally, a package may also define tests to ensure that it is functioning as expected.

Elastic Packages have a certain, well-defined structure. This structure is described by the [Package Specification](https://github.com/elastic/package-spec). The repository is also used for discussions about extending the specification (with proposals).

The Elastic Integrations are distributed with the [Package Storage](https://github.com/elastic/package-storage)
and exposed for [Kibana](https://github.com/elastic/kibana) via the [Package Registry](https://github.com/elastic/package-registry/).

The official builder tool for Elastic Integrations is [`elastic-package`](https://github.com/elastic/elastic-package).

## Contributing

Please review the [Contributing Guide](CONTRIBUTING.md) to learn how to build and develop packages, understand the release procedure and
explore the builder tools.
