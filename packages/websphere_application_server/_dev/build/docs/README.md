# WebSphere Application Server

This Elastic integration is used to collect the following metrics from [IBM WebSphere Application Server](https://www.ibm.com/cloud/websphere-application-server):

   - JDBC metrics
   - Servlet metrics
   - ThreadPool metrics

This integration uses Prometheus to collect above metrics.

To open Prometheus endpoint read following [instructions](https://www.ibm.com/docs/en/was/9.0.5?topic=mosh-displaying-pmi-metrics-in-prometheus-format-metrics-app).

## JDBC

This data stream collects JDBC (Java Database Connectivity) related metrics.

{{event "jdbc"}}

{{fields "jdbc"}}

## Servlet

This data stream collects Servlet related metrics.

{{event "servlet"}}

{{fields "servlet"}}

## ThreadPool

This data stream collects Thread related metrics.

{{event "threadpool"}}

{{fields "threadpool"}}
