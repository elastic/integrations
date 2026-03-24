---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/build-overview.html
---

# Overview and prerequisites [build-overview]

## Understand {{stack}} concepts [understand-concepts]

Before building an integration, you should have an understanding of the following {{stack}} concepts:

* [Data streams](https://www.elastic.co/docs/manage-data/data-store/data-streams): Logic abstraction for time-series data. 
* [Ingest pipelines](https://www.elastic.co/docs/manage-data/ingest/transform-enrich/ingest-pipelines): Preprocessing and enrichment of incoming data.
* [Mappings](https://www.elastic.co/docs/manage-data/data-store/mapping): Define the structure and types of your data.
* [Package specification](/extend/package-spec.md) to understand the required structure and fields for your integration package.

## Set up your development environment [setup-env]

* Install the [`elastic-package`](/extend/elastic-package.md) CLI tool. Using `elastic-package` is recommended for integration maintainers as it provides crucial utilities and scripts for building out integrations.
* Clone the [integrations repository](https://github.com/elastic/integrations) if you plan to contribute to official packages.

