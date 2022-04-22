# WebSphere Application Server

This elastic integration is used to collect [WebSphere Application Server](https://www.ibm.com/cloud/websphere-application-server) metrics and logs as follows:

   - ThreadPool metrics

This integration uses Prometheus to collect above metrics.

To open Prometheus endpoint read following [instructions](https://www.ibm.com/docs/en/was/9.0.5?topic=mosh-displaying-pmi-metrics-in-prometheus-format-metrics-app).

## ThreadPool

This data stream collects Thread related metrics.

{{event "threadpool"}}

{{fields "threadpool"}}
