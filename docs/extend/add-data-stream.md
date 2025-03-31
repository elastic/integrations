---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/add-a-data-stream.html
---

# Add a data stream [add-a-data-stream]

A data stream is a logical sub-division of an integration package, dealing with a specific observable aspect of the service or product being observed. For example, the [Apache integration](https://github.com/elastic/integrations/tree/main/packages/apache) has three data streams, each represented by a separate folder of assets in the `data_stream` directory:

```text
apache
└───data_stream
│   └───access
│   └───error
│   └───status
```

::::{admonition}
**Data streams** allow you to store time series data across multiple indices while giving you a single named resource for requests.

A data stream defines multiple {{es}} assets, like index templates, ingest pipelines, and field definitions. These assets are loaded into {{es}} when a user installs an integration using the {{fleet}} UI in {{kib}}.

A data stream also defines a policy template. Policy templates include variables that allow users to configure the data stream using the {{fleet}} UI in {{kib}}. Then, the {{agent}} interprets the resulting policy to collect relevant information from the product or service being observed. Policy templates can also define an integration’s supported [`deployment_modes`](/extend/define-deployment-modes.md#deployment_modes).

See [data streams](docs-content://reference/fleet/data-streams.md) for more information.

::::


Bootstrap a new data stream using the TUI wizard. In the directory of your package, run:

```bash
elastic-package create data-stream
```

Follow the prompts to name, title, and select your data stream type. Then, run this command each time you add a new data stream to your integration.

Next, manually adjust the data stream:

* define required variables
* define used fields
* define ingest pipeline definitions (if necessary)
* update the {{agent}}'s stream configuration
