# Elastic Integrations

[![Build Status](https://beats-ci.elastic.co/job/ingest-manager/job/integrations/job/master/badge/icon)](https://beats-ci.elastic.co/job/ingest-manager/job/integrations/job/master/)

This repository contains sources of the Elastic Integrations - packages defining data streams to observe the same product (logs, metrics, traces).
A package may contain configuration of the [Elastic-Agent](https://github.com/elastic/beats/tree/master/x-pack/elastic-agent), dashboards, visualizations,
images, tests, documentation, etc.

The format of a package is described in the [Package Spec](https://github.com/elastic/package-spec), which is also used
for extending the specification (with proposals).

The Elastic Integrations are distributed with the [Package Storage](https://github.com/elastic/package-storage)
and exposed for [Kibana](https://github.com/elastic/kibana) via the [Package Registry](https://github.com/elastic/package-registry/).

The official builder tool for the Elastic Integrations is the [elastic package](https://github.com/elastic/elastic-package).

## Contributing

Please review the [CONTRIBUTING](CONTRIBUTING.md) guide to learn how to build and develop packages.