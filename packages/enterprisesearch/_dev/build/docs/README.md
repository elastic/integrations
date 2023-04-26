# Enterprise search

The `enterprisesearch` package collects metrics of Enterprise search. 

## Metrics

### Usage for Stack Monitoring

The `enterprisesearch` package can be used to collect metrics shown in our Stack Monitoring
UI in Kibana.

### Health

Fetch and ingest Enterprise Search solution health information from the [Health API](https://www.elastic.co/guide/en/enterprise-search/current/monitoring-apis.html#health-api).

{{event "health"}}

{{fields "health"}}

### Stats

Fetch and ingest Enterprise Search solution statistics information from the [Stats API](https://www.elastic.co/guide/en/enterprise-search/current/monitoring-apis.html#stats-api).

{{event "stats"}}

{{fields "stats"}}
