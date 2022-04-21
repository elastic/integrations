# WebSphere Application Server

This integration is used to collect [WebSphere Application Server](https://www.ibm.com/cloud/websphere-application-server) metrics as follows:

   - JDBC Metrics
   - ThreadPool Metrics
   - Servlet Metrics
   - Session Manager Metrics

This integration uses Prometheus to collect above metrics.

To open Prometheus endpoint read following [instructions](https://www.ibm.com/docs/en/was/9.0.5?topic=mosh-displaying-pmi-metrics-in-prometheus-format-metrics-app).

## Servlet

This data stream collects Servlet Metrics.

{{event "servlet"}}

{{fields "servlet"}}
