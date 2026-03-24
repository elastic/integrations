# Osquery Manager integration

With this integration, you can centrally manage [Osquery](https://osquery.io/) deployments to Elastic Agents in your Fleet and query host data through distributed SQL. 

This integration adds an Osquery UI in Kibana where you can:

 - Run live queries for one or more agents
 - View a history of past queries and their results
 - Schedule queries to capture OS state changes over time
 - Save queries and build a library of queries for specific use cases

Osquery results are stored in Elasticsearch, so that you can use the power of the stack to search, analyze, and visualize Osquery data.

## Investigate with Osquery
For information about using Osquery, refer to the [Osquery Kibana documentation](https://www.elastic.co/docs/solutions/security/investigate/osquery). 
This includes information about required privileges; how to run, schedule, and save queries; how to map osquery fields to ECS; and other useful information about managing Osquery with this integration.

For information about Osquery tables, refer to the [Osquery schema documentation](https://osquery.io/schema) and [Osquery Extension for Elastic](https://github.com/elastic/beats/blob/main/x-pack/osquerybeat/ext/osquery-extension/README.md).
