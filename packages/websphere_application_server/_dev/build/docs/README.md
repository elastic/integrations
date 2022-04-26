# WebSphere Application Server

This Elastic integration is used to collect [WebSphere Application Server](https://www.ibm.com/cloud/websphere-application-server) metrics as follows:

   - Session Manager metrics

This integration uses Prometheus to collect above metrics.

To open Prometheus endpoint read following [instructions](https://www.ibm.com/docs/en/was/9.0.5?topic=mosh-displaying-pmi-metrics-in-prometheus-format-metrics-app).

### Session Manager

This data stream collects metrics related to Sessions.

{{event "session_manager"}}

{{fields "session_manager"}}
