---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/index.html
  - https://www.elastic.co/guide/en/integrations-developer/current/what-is-an-integration.html
---

# What is an integration? [what-is-an-integration]

An Elastic integration is a collection of assets that defines how to observe a specific product or service with the {{stack}}:

* Data ingest, storage, and transformation rules
* Configuration options
* Pre-built, custom dashboards and visualizations
* Documentation
* Tests

Integrations have a strict, well-defined structure, and offer a number of benefits over other ingest options:

* Structured around the service that is being observed—​not the monitoring agent
* Easy, less error-prone configuration
* Fewer monitoring agents for users to install
* Deploy in just a few clicks
* Decoupled release process from the {{stack}}


## Integration lifecycle [how-integrations-work]

1. Create a source package

    All integrations start as a source package. You’ll find most Elastic integrations in the [`elastic/integrations`](https://github.com/elastic/integrations) repository, but a package can live anywhere.

    All packages must adhere to the [package specification](/extend/package-spec.md) — a formal spec used for the creation and validation of new or updated integrations.

2. Publish the integration to the package registry

    Once an integration (package) has been created, it needs to be built. Built integrations are served up via the [{{package-registry}}](https://github.com/elastic/package-registry). The {{fleet}} UI in {{kib}} connects to the {{package-registry}} and allows users to discover, install, and configure Elastic Packages. The {{package-registry}} can also be [deployed on-premise in air-gapped environments](docs-content://reference/fleet/air-gapped.md#air-gapped-diy-epr).

3. Install the integration

    Using {{fleet}} in {{kib}}, install the integration and add it to an {{agent}} policy. When you install a package, its assets are unpacked and installed into {{es}} and {{kib}} using {{stack}} APIs. In addition, configuration for the package is persisted in {{es}} as an {{agent}} policy.

4. Add the policy with the integration to an {{agent}}.

    Once the policy with an integration is added to an {{agent}}, the {{agent}} will begin to collect and ship data to the {{stack}} based on the Elastic integration.

    Package assets may come into play here. For example, if a package installed ingest pipelines, those will intercept the data and transform it before it is indexed.

5. Visualize the results

    Integrations can and should ship with custom dashboards and visualizations that are installed with the integration. Use these for a tailored view of your {{observability}} data.



