# First EPSS

The First EPSS integration allows you to ingest data from First EPSS API. The Exploit Prediction Scoring System (EPSS) is a data-driven effort for estimating the likelihood (probability) that a software vulnerability will be exploited in the wild..

## Data streams

The First EPSS integration collects one type of data streams: logs.

<!-- If applicable -->
<!-- **Logs** help you keep a record of events happening in {service}.
Log data streams collected by the {name} integration include {sample data stream(s)} and more. See more details in the [Logs](#logs-reference). -->

<!-- If applicable -->
<!-- **Metrics** give you insight into the state of {service}.
Metric data streams collected by the {name} integration include {sample data stream(s)} and more. See more details in the [Metrics](#metrics-reference). -->

<!-- Optional: Any additional notes on data streams -->

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

<!--
	Optional: Other requirements including:
	* System compatibility
	* Supported versions of third-party products
	* Permissions needed
	* Anything else that could block a user from successfully using the integration
-->

## Setup

<!-- Any prerequisite instructions -->

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

<!-- Additional set up instructions -->

<!-- If applicable -->
<!-- ## Logs reference -->

<!-- Repeat for each data stream of the current type -->
<!-- ### {Data stream name}

The `{data stream name}` data stream provides events from {source} of the following types: {list types}. -->

<!-- Optional -->
<!-- #### Example

An example event for `{data stream name}` looks as following:

{code block with example} -->

<!-- #### Exported fields

{insert table} -->

<!-- If applicable -->
<!-- ## Metrics reference -->

<!-- Repeat for each data stream of the current type -->
<!-- ### {Data stream name}

The `{data stream name}` data stream provides events from {source} of the following types: {list types}. -->

<!-- Optional -->
<!-- #### Example

An example event for `{data stream name}` looks as following:

{code block with example} -->

<!-- #### Exported fields

{insert table} -->

<!-- Repeat for both Logs and Metrics if applicable -->
## Logs

<!-- Repeat for each data stream of the current type -->
### EPSS

The `epss` data stream retrieves the full list of EPSS scores of CVEs every interval from the the EPSS API url `https://api.first.org/data/v1/epss`

#### Exported fields

{{fields "epss"}}