# Elasticsearch

The `elasticsearch` module collects metrics about elasticsearch.

## Compatibility

The `elasticsearch` module works with elasticsearch 6.7.0 and later.

## Usage for Stack Monitoring

The `elasticsearch` package can be used to collect logs and metrics shown in our Stack Monitoring
UI in Kibana.

## Module-specific configuration notes

Like other package, `elasticsearch` metrics collection accepts a `hosts` configuration setting.
This setting can contain a list of entries. The related `scope` setting determines how each entry in
the `hosts` list is interpreted by the module.

* If `scope` is set to `node` (default), each entry in the `hosts` list indicates a distinct node in an
  elasticsearch cluster.
* If `scope` is set to `cluster`, each entry in the `hosts` list indicates a single endpoint for a distinct
  elasticsearch cluster (for example, a load-balancing proxy fronting the cluster).
