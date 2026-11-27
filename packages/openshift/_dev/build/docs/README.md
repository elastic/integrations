{{- generatedHeader }}
{{/*
This template can be used as a starting point for writing documentation for your new integration. For each section, fill in the details
described in the comments.

Find more detailed documentation guidelines in https://www.elastic.co/docs/extend/integrations/documentation-guidelines
*/}}
# Red Hat OpenShift Logging Integration for Elastic

## Overview
{{/* Complete this section with a short summary of what data this integration collects and the service it integrates with. */}}
The Red Hat OpenShift Logging integration for Elastic processes the logs that the [Red Hat OpenShift Logging Operator](https://docs.redhat.com/en/documentation/red_hat_openshift_logging/) forwards from an OpenShift cluster. The operator's collector sends application, infrastructure, and audit logs directly to Elasticsearch. This integration maps them to the Elastic Common Schema (ECS) and stores each log type in its own data stream.

### Compatibility
{{/* Complete this section with information on what 3rd party software or hardware versions this integration is compatible with */}}
This integration is compatible with Red Hat OpenShift Logging 6.x, which configures log forwarding with the `ClusterLogForwarder` resource of the `observability.openshift.io/v1` API. It was tested with the Vector collector image of Red Hat OpenShift Logging 6 (Vector 0.54).

Red Hat OpenShift Logging 5.x is not supported. Its Elasticsearch output writes to the fixed `app-write`, `infra-write`, and `audit-write` indices, which this integration doesn't provide.

### How it works
{{/* Add a high level overview on how this integration works. For example, does it collect data from API calls or receiving data from a network or file.*/}}
This integration doesn't use Elastic Agent. The collector of the OpenShift Logging Operator sends logs to the Elasticsearch `_bulk` API:

1. A `ClusterLogForwarder` output of type `elasticsearch` writes every record to the `logs-openshift-default` data stream.
2. Routing rules of that data stream forward each record by its `log_type` to the `openshift.application`, `openshift.infrastructure`, or `openshift.audit` data stream.
3. The ingest pipeline of the target data stream maps the record to ECS.

## What data does this integration collect?
{{/* Complete this section with information on what types of data the integration collects, and link to reference documentation if available
*/}}
The Red Hat OpenShift Logging integration collects log messages of the following types:
* Application logs: container logs of user workloads, from all namespaces except `default`, `kube-*`, and `openshift-*`.
* Infrastructure logs: container logs from the `default`, `kube-*`, and `openshift-*` namespaces, and the journald logs of the nodes.
* Audit logs: audit events of the Kubernetes API server, the OpenShift API server, and the OAuth servers; Linux audit (`auditd`) records of the nodes; and OVN-Kubernetes ACL logs of network policies, admin network policies, and egress firewalls.

### Supported use cases
{{/* Add details on the use cases that can be enabled by using this integration. Explain why a user would want to install and use this integration. */}}
- Search and analyze the logs of OpenShift workloads and platform components with Kubernetes metadata such as namespace, pod, container, and owner.
- Investigate who did what in the cluster with API audit events mapped to ECS user, source, URL, and orchestrator fields.
- Monitor node security events from Linux audit records and network policy decisions from OVN-Kubernetes ACL logs.
- Collect OpenShift logs without running Elastic Agent in the cluster, using the log collector that OpenShift already provides.

## What do I need to use this integration?
{{/* List any Elastic or vendor-specific prerequisites needed before starting to install the integration. For example, Elastic self-managed or cloud deployment, or a vendor-specific credentials or accounts */}}
- An Elastic deployment, self-managed or on Elastic Cloud, that the OpenShift cluster can reach over HTTPS.
- An OpenShift cluster with the Red Hat OpenShift Logging Operator 6.x installed.
- Permission to create a `ClusterLogForwarder`, a service account, and a secret in the cluster.

## How do I deploy this integration?

This integration has no Elastic Agent input. You install its assets in Kibana and configure the OpenShift Logging Operator to send logs to Elasticsearch.

### Set up steps in Kibana
{{/* List the steps that are required to set up the integration in Kibana.
This includes how to add the integration, and how to configure the integration, with descriptions of each available configuration option.

If multiple input types are supported, add instructions for each in a subsection.
*/}}
1. In Kibana, go to **Management** > **Integrations** and search for **Red Hat OpenShift Logging**.
2. Open the integration, go to the **Settings** tab, and click **Install Red Hat OpenShift Logging assets**.

Then create a user for the collector. The collector needs to create documents in the OpenShift data streams. For example, create a role with these privileges and assign it to a user:

```json
POST _security/role/openshift_logging_writer
{
  "indices": [
    {
      "names": ["logs-openshift*-*"],
      "privileges": ["auto_configure", "create_doc"]
    }
  ]
}
```

### Set up steps in OpenShift
{{/* List the steps that are required to set up the 3rd party system to send data to Elastic.
This should be specific to the steps needed to set up the 3rd party system to send data to Elastic. It should not include generic information about how to install or set up the 3rd party system itself.
*/}}
1. Create a secret with the credentials of the Elasticsearch user in the `openshift-logging` namespace:

   ```sh
   oc -n openshift-logging create secret generic elasticsearch-credentials \
     --from-literal=username=<user> --from-literal=password=<password>
   ```

2. Create a service account for the collector and allow it to collect the log types you need, as described in the OpenShift Logging documentation, for example:

   ```sh
   oc -n openshift-logging create serviceaccount logcollector
   oc adm policy add-cluster-role-to-user collect-application-logs -z logcollector -n openshift-logging
   oc adm policy add-cluster-role-to-user collect-infrastructure-logs -z logcollector -n openshift-logging
   oc adm policy add-cluster-role-to-user collect-audit-logs -z logcollector -n openshift-logging
   ```

3. Create a `ClusterLogForwarder` with an Elasticsearch output. The `index` must be `logs-openshift-default`, or `logs-openshift-<namespace>` to use another data stream namespace:

   ```yaml
   apiVersion: observability.openshift.io/v1
   kind: ClusterLogForwarder
   metadata:
     name: elastic
     namespace: openshift-logging
   spec:
     serviceAccount:
       name: logcollector
     outputs:
       - name: elasticsearch
         type: elasticsearch
         elasticsearch:
           url: https://elasticsearch.example.com:443
           version: 8
           index: logs-openshift-default
           authentication:
             username:
               key: username
               secretName: elasticsearch-credentials
             password:
               key: password
               secretName: elasticsearch-credentials
     filters:
       - name: parse-json
         type: parse
     pipelines:
       - name: all-logs
         inputRefs:
           - application
           - infrastructure
           - audit
         filterRefs:
           - parse-json
         outputRefs:
           - elasticsearch
   ```

   - `version: 8` is required for Elasticsearch 8.0 and later. With an older value the collector sends the `_type` field, which Elasticsearch 8 rejects.
   - The `parse` filter is optional. It parses JSON container log lines into `openshift.structured`.
   - Add a `tls` section with a CA bundle when the certificate of Elasticsearch isn't signed by a CA that the cluster trusts.
   - The collector can't take an Elasticsearch API key from a secret. To use an API key anyway, set it as a header of the output instead of `authentication`: `headers: {Authorization: "ApiKey <base64 encoded id:api_key>"}`. The key is then stored in plain text in the `ClusterLogForwarder` resource.

#### Vendor resources
{{/* Add vendor documentation links that are specific to the steps needed to set up the vendor system to send data to Elastic. Exclude this section if no vendor setup links are available. */}}
- [Cluster Logging Operator: ClusterLogForwarder](https://github.com/openshift/cluster-logging-operator/blob/master/docs/administration/clusterlogforwarder.adoc)
- [Red Hat OpenShift: Audit logging for network security (OVN-Kubernetes ACL logs)](https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/network_security/logging-network-security)

### Validation
{{/* In this section, describe the actions required to validate that the integration is working properly, and data is flowing into Elasticsearch.
If required, list the steps needed in the vendor product to start sending events or trigger alerts.
Then list how to validate that the data is in Elasticsearch, using Kibana. This could be which indices to check in the Discover table, or which built in dashboards to look at to see the data.
*/}}
1. Check that the collector pods in the `openshift-logging` namespace are running and that their logs show no Elasticsearch errors: `oc -n openshift-logging logs -l app.kubernetes.io/component=collector`.
2. In Kibana, go to **Discover** and select the `logs-openshift.application-*`, `logs-openshift.infrastructure-*`, or `logs-openshift.audit-*` data stream.
3. Check that the documents have `event.dataset` set to `openshift.application`, `openshift.infrastructure`, or `openshift.audit`.

## Troubleshooting
{{/* The troubleshooting section should contain troubleshooting for common issues specific to this integration. Do not include generic troubleshooting information. Where appropriate, include details specific to each input type.
Whenever possible, link to the troubleshooting documentation provided by the third-party software.

IMPORTANT: Use plain text for issue descriptions, NOT bold. Example:
- No data is being collected: Verify network connectivity and credentials
- TCP framing issues: Check that both sides use the same framing method
Do NOT use **bold** for issue names like "**No data is being collected**:".
*/}}
- Records stay in the `logs-openshift-default` data stream: The routing rules only forward records whose `log_type` is `application`, `infrastructure`, or `audit`. Check the `log_type` field of these records.
- The collector logs `security_exception` or `action [indices:data/write/bulk[s]] is unauthorized`: The Elasticsearch user lacks `create_doc` or `auto_configure` on `logs-openshift*-*`. The routing rules write to `logs-openshift.<log type>-<namespace>`, so the privileges must cover these data streams as well.
- The collector logs `index_not_found_exception` or writes to an index named `app-write`: The output still uses the defaults of OpenShift Logging 5. Set `index: logs-openshift-default` in the output.
- Application logs have no `message` field: The `parse` filter removes `message` when it parses a log line as JSON. The integration copies the `message` or `msg` key of the parsed line back into `message`; other keys are available under `openshift.structured`.

## Performance and scaling
{{/* Add any vendor specific performance and scaling information to this section.
Performance and scaling information should be specific to sending data to Elasticsearch. It should not include information about the vendor product itself or generic information about performance and scaling.
*/}}
The collector runs on every node of the cluster and sends bulk requests directly to Elasticsearch. Tune the batch size and the delivery mode in the `tuning` section of the output, as described in the OpenShift Logging documentation. Every record passes through the ingest pipeline of the `openshift` data stream and then the pipeline of its target data stream.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Vendor documentation links
{{/* Add vendor documentation links which provide useful general information about the integration.*/}}
- [Red Hat OpenShift Logging documentation](https://docs.redhat.com/en/documentation/red_hat_openshift_logging/)
- [ViaQ data model of the OpenShift Logging collector](https://github.com/openshift/cluster-logging-operator/blob/master/docs/reference/datamodels/viaq/v1.adoc)

### Data streams
{{/* Repeat all information in this section for each data stream the package collects.*/}}

#### openshift

The `openshift` data stream receives all records from the collector and routes them to the data stream of their log type. Records with another log type stay in this data stream unchanged.

##### openshift fields

{{ fields "openshift" }}

#### application

The `application` data stream provides container logs of user workloads, with Kubernetes metadata of the pod and container.

##### application fields

{{ fields "application" }}

#### infrastructure

The `infrastructure` data stream provides container logs of the OpenShift platform namespaces and the journald logs of the nodes.

##### infrastructure fields

{{ fields "infrastructure" }}

#### audit

The `audit` data stream provides Kubernetes API server, OpenShift API server, and OAuth server audit events; Linux audit records of the nodes; and OVN-Kubernetes ACL logs.

##### audit fields

{{ fields "audit" }}

{{/* Export ILM Policies
     This accepts a list of data stream names as arguments and documents one policy
     per data stream. If no arguments are provided, data streams are auto-discovered by
     scanning for data_stream/<name>/elasticsearch/ilm/ directories and
     data_stream/<name>/lifecycle.yml files (lifecycle.yml takes precedence when both exist).

     If there are no policies defined, this renders as an empty string (no heading).
*/}}
{{ ilm }}

{{/* Export Transforms
     This will export the transforms used by this integration.
     If there are no transforms defined, this renders as an empty string (no heading).
*/}}
{{ transform }}
