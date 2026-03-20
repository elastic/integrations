---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html
---

# Documentation guidelines [documentation-guidelines]

The goal of each integration's documentation is to:

* Describe the benefits the integration offers and how Elastic can help with different use cases. 
* Specify requirements, including system compatibility, supported versions of third-party products, permissions needed, and more.
* Provide a list of collected fields, including data and metric types for each field. This information is useful while evaluating the integration, interpreting collected data, or troubleshooting issues.
* Each integration document should contain the following sections

    * [Overview](#idg-docs-overview)
    * [What data does this integration collect?](#idg-data-collected)
    * [What do I need to use this integration?](#idg-requirements)
    * [How do I deploy this integration?](#idg-docs-setup)
    * [Troubleshooting](#idg-docs-troubleshooting)
    * [Performance and scaling](#idg-docs-performance-scaling)
    * [Reference](#idg-docs-reference)

::::{tip}
**Getting started quickly:** Run `elastic-package create package` to generate a new package with a README template that follows this structure. The generated template includes placeholder content for each section and has [documentation structure validation](finishing-touches.md#documentation-structure-validation) enabled by default, so `elastic-package check` will verify your README includes all required sections.
::::

### Writing documentation templates

Documentation files are written as templates at `_dev/build/docs/*.md` and are processed during `elastic-package build` to generate the final documentation in `docs/`.

Key considerations:

* **Markdown syntax:** Documentation files use standard Markdown syntax.
* **Template functions:** Use template functions like `{{ fields "data_stream" }}` and `{{ event "data_stream" }}` to automatically generate field tables and sample events. See [template functions](finishing-touches.md#template-functions) for the complete list.
* **Linking to Elastic docs:** Use the `{{ url "link-id" "Caption" }}` function to create links to Elastic documentation. This ensures links remain valid as documentation URLs change. Available link IDs are defined in [`links_table.yml`](https://github.com/elastic/elastic-package/blob/main/scripts/links_table.yml).

### Overview [idg-docs-overview]

The **Overview** section explains what the integration does, what the main uses cases are, and contains the following subsections:

* **Compatibility**

   Indicates which versions, deployment methods, or architectures of the third party software this integration compatible with.

* **How it works**

   Provides a high-level overview on how the integration collects data.

### What data does this integration collect? [idg-data-collected]

This section should include:

* The types of data collected by the integration
* Supported use cases

### What do I need to use this integration? [idg-requirements]

This section indicates what is required to use this integration:

* Elastic prerequisites (for example, a self-managed or Cloud deployment)
* Credentials or an admin account for the third-party software

### How do I deploy this integration? [idg-docs-setup]

This section refers to the Observability [Getting started guide](docs-content://solutions/observability/get-started.md) for generic, step-by-step instructions, and should also include the following additional setup instructions:

**Onboard and configure**

* How do I install the Agent and deploy this integration?
* Which agent deployment methods are acceptable? Fleet? Standalone? 
* Is agentless deployment supported for this integration?
* What data, input, fields, or authentication tokens must be configured during integration deployment? What values should they have? 

**Validation**

* How can I test whether the integration is working? Include example commands or test files if applicable.

::::{note}
When possible, use links to point to third-party documentation for configuring non-Elastic products since workflows may change without notice.
::::

### Troubleshooting [idg-docs-troubleshooting]

The troubleshooting section should include details specific to each input type, along with general guidance for resolving common issues encountered when deploying this integration. Whenever possible, link to the troubleshooting documentation provided by the third-party software.

### Performance and scaling [idg-docs-performance-scaling]

Based on the input, this section should explain how to scale the integration and what are the best types of scaling architecture to use, including benchmarking recommendations.

### Reference [idg-docs-reference]

There can be any number of reference sections, for example:

* ECS Field Reference
* Metrics reference
* Logs reference
* Inputs used in this integration
* APIs used to collect data
* Changelog 

Each reference section should contain detailed information about:

* A list of the log or metric types supported within the integration and a link to the relevant third-party documentation.
* (Optional) An example event in JSON format.
* Exported fields for logs, metrics, and events with actual types (for example, `counters`, `gauges`, `histograms` vs. `longs` and `doubles`). Fields should be generated using the instructions in [Fine-tune the integration](https://github.com/elastic/integrations/blob/main/docs/fine_tune_integration.md).
* ML Modules jobs.
