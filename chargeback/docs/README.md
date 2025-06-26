# Chargeback

_Technical preview: This module is developed by Elastic's Customer Engineering team. Please report any issues to the Elastician who shared this integration with you._

The Chargeback module provides FinOps visibility into Elastic usage across tenants. By integrating data from the [**Elasticsearch Service Billing**](https://www.elastic.co/docs/reference/integrations/ess_billing/) and [**Elasticsearch**](https://www.elastic.co/docs/reference/integrations/elasticsearch/) integrations, it enables the determination of the value provided by each deployment, data stream, and tier. This functionality allows Centre of Excellence (CoE) teams to accurately allocate costs back to the appropriate tenant.

## What is FinOps?

FinOps is an operational framework and cultural practice aimed at maximizing the business value of cloud usage. It facilitates timely, data-driven decision-making and promotes financial accountability through collaboration among engineering, finance, and business teams.

## Purpose

The Chargeback module assists organizations in addressing a crucial question:

> **"How is my organisation consuming the Elastic solution, and to which tenants can I allocate these costs?"**

This module provides a breakdown of Elastic Consumption Units (ECUs) per:

- Deployment
- Data tier
- Data stream
- Day

Currently, Chargeback calculations consider only Elasticsearch data nodes. Contributions from other assets, like Kibana or ML nodes, are assumed to be shared proportionally among tenants. To incorporate indexing, querying, and storage in a weighted manner, a blended value is created using the following default weights (modifiable):
- Indexing: 20 (applicable only to the hot tier)
- Querying: 20
- Storage: 40

This weighting means storage contributes most to the blended cost calculation, with indexing contributing only on the hot tier. Adjust these weights based on your organization's needs and best judgment.

Chargeback data can be viewed in the `[Chargeback] Cost and Consumption breakdown` dashboard.

![Cost and Consumption breakdown](../img/chargeback.png)

## Requirements

To use this module, the following prerequisites must be met:

- The monitoring cluster, where this integration is installed, must be on version 8.18.0+ due to its use of [ES|QL LOOKUP JOIN](https://www.elastic.co/docs/reference/query-languages/esql/esql-lookup-join).
- The [**Elasticsearch Service Billing**](https://www.elastic.co/docs/reference/integrations/ess_billing/) integration (v1.4.1+) must be installed and running.
- The [**Elasticsearch**](https://www.elastic.co/docs/reference/integrations/elasticsearch/) integration (v1.16.0+) must be installed and collecting [usage data](https://www.elastic.co/docs/reference/integrations/elasticsearch/#indices-and-data-streams-usage-analysis) from all relevant deployments.
- The Transform named `logs-elasticsearch.index_pivot-default-{VERSION}` must be running, which is an asset of the **Elasticsearch** integration.


This integration must be installed on the **Monitoring cluster** where the above mentioned relevant usage and billing data is collected.
