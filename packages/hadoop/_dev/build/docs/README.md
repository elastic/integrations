# Hadoop

The Hadoop integration collects and parses data from the Hadoop Events APIs and using the Jolokia Metricbeat Module.

## Compatibility

This module has been tested against `Hadoop version 3.3.1`

## Requirements

In order to ingest data from Hadoop, you must know the full hosts for the NameNode, DataNode, Cluster Metrics, Node Manager and the Hadoop Events API.

## Metrics

### Application Metrics

This is the `application_metrics` dataset.

{{event "application_metrics"}}

{{fields "application_metrics"}}

### Expanded Cluster Metrics

This is the `expanded_cluster_metrics` dataset.

{{event "expanded_cluster_metrics"}}

{{fields "expanded_cluster_metrics"}}

### Jolokia Metrics

This is the `jolokia_metrics` dataset.

{{event "jolokia_metrics"}}

{{fields "jolokia_metrics"}}