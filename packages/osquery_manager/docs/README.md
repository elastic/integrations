# Osquery Manager integration

With this integration, you can centrally manage [Osquery](https://osquery.io/) deployments to Elastic Agents in your Fleet and query host data through distributed SQL. 

This integration adds an Osquery UI in Kibana where you can:

 - Run live queries for one or more agents
 - View a history of past queries and their results
 - Schedule queries to capture OS state changes over time
 - Save queries and build a library of queries for specific use cases

Osquery results are stored in Elasticsearch, so that you can use the power of the stack to search, analyze, and visualize Osquery data.

## Documentation
For information about using Osquery, see the [Osquery Kibana documentation](https://www.elastic.co/guide/en/kibana/current/osquery.html). 
This includes information about required privileges; how to run, schedule, and save queries; how to map osquery fields to ECS; and other useful information about managing Osquery with this integration.

## Exported Fields
For a full list of fields that can be returned in osquery results, see the [Exported Fields reference](https://www.elastic.co/guide/en/kibana/current/exported-fields-osquery.html) in the Kibana documentation. 
