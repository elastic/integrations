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

## How to add a data stream [how-to]

1. Boostrap a new data stream

In your package directory, run:

```bash
elastic-package create data-stream
```

Follow the prompts to set the name, title, and type (logs, metrics, etc.) for the data stream. Repeat this command for each new data stream you want to add.

2. Configure the data stream

After bootstrapping, manually adjust the generated files to suit your use case:

* Define required variables:
In the policy template, specify variables that users can configure (e.g., paths, ports, log levels).
* Define used fields:
Edit the fields/ files to describe the structure and types of data your stream will ingest.
* Define ingest pipeline definitions:
If needed, create or update ingest pipelines to parse, enrich, or transform incoming data before it’s indexed.
* Update the {{agent}} stream configuration:
Ensure the {{agent}}’s stream configuration matches your data collection requirements and references the correct variables and pipelines.

3. How data streams are used

* When the integration is installed, each data stream is registered in {{es}} as a managed, time-based resource.
* Data sent to the data stream is automatically routed to the correct backing indices, with lifecycle management (rollover, retention) handled by Elasticsearch.
* Users can query, visualize, and analyze data from each stream in {{kib}}, using the single data stream name (e.g., `logs-apache.access`).
