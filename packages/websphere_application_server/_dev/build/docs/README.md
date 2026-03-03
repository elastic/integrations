# WebSphere Application Server

This Elastic integration is used to collect the following metrics from [IBM WebSphere Application Server](https://www.ibm.com/cloud/websphere-application-server):

   - JDBC metrics
   - Servlet metrics
   - Session Manager metrics
   - ThreadPool metrics

This integration uses Prometheus to collect above metrics.

To open Prometheus endpoint read following [instructions](https://www.ibm.com/docs/en/was/9.0.5?topic=mosh-displaying-pmi-metrics-in-prometheus-format-metrics-app).

## Compatibility

This integration has been tested against WebSphere Application Server traditional version `9.0.5.17`.

### Troubleshooting

If host.ip is shown conflicted under ``metrics-*`` data view, then this issue can be solved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream) the ``JDBC``, ``Servlet``, ``Session Manager`` and ``ThreadPool`` data stream's indices.

## JDBC

This data stream collects JDBC (Java Database Connectivity) related metrics.

{{event "jdbc"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "jdbc"}}

## Servlet

This data stream collects Servlet related metrics.

{{event "servlet"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "servlet"}}

### Session Manager

This data stream collects metrics related to Sessions.

{{event "session_manager"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "session_manager"}}

## ThreadPool

This data stream collects Thread related metrics.

{{event "threadpool"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "threadpool"}}
