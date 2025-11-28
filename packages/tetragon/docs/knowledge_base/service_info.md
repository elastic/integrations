# Service Info

## Common use cases

- **Kubernetes Security Observability**: Monitor and analyze security events from containerized applications running in Kubernetes environments, providing real-time visibility into process executions, system calls, and other kernel-level activities.

- **Runtime Threat Detection**: Detect and respond to security threats by analyzing process behavior, file access patterns, and system call activities at the kernel level using eBPF technology.

- **Compliance and Audit Logging**: Capture detailed audit trails of process executions, exits, and kernel probe events with Kubernetes context (namespace, pod, workload) for compliance and forensic analysis.

- **Container Security Monitoring**: Track process lifecycle events and system activities within containers, correlating security events with Kubernetes metadata such as pod labels, namespaces, and workload types.

## Data types collected

- **Process Execution Events** (`process_exec`): Details about process starts including executable paths, arguments, working directory, user IDs, process IDs, parent-child relationships, and associated Kubernetes pod/container metadata.

- **Process Exit Events** (`process_exit`): Information about process terminations including exit status, signals, and timing information with full process context.

- **Kernel Probe Events** (`process_kprobe`): System call and kernel function monitoring data including file operations, capability checks, namespace information, and custom policy-based events with function names, arguments, and return values.

- **Kubernetes Metadata**: Pod names, namespaces, container IDs, image names, workload types (Deployment, Pod, etc.), pod labels, and node names associated with all security events.

## Compatibility

- **Kubernetes**: Requires a Kubernetes cluster environment where Tetragon can be deployed as a DaemonSet.

- **Linux Kernel**: Requires Linux kernel with eBPF support.

- **Elastic Stack**: Compatible with Kibana versions 8.13.0 or higher, and 9.0.0 or higher.

- **Integration Type**: Uses Filebeat for log forwarding (Elastic Agent is not supported for this integration).

## Scaling and Performance

- **eBPF-based Architecture**: Tetragon utilizes eBPF (extended Berkeley Packet Filter) technology to provide deep kernel-level observability with minimal performance overhead, operating directly within the Linux kernel.

- **Event Filtering**: Performance can be optimized by configuring `tetragon.exportAllowList` and `tetragon.exportDenyList` Helm values to control which events are exported, reducing data volume and processing requirements.

- **Kubernetes DaemonSet Deployment**: Tetragon runs as a DaemonSet in Kubernetes, automatically scaling across cluster nodes to provide consistent monitoring coverage.

# Set Up Instructions

## Vendor prerequisites

- A running Kubernetes cluster with nodes that support eBPF.

- Helm 3.x installed for deploying Tetragon via Helm charts.

- Administrative access to the Kubernetes cluster to create resources in the `kube-system` namespace.

- Sufficient permissions to create ConfigMaps, deploy DaemonSets, and configure volume mounts.

## Elastic prerequisites

- Elasticsearch and Kibana version 8.13.0 or higher (or 9.0.0+) for data storage, search, and visualization.

- Elasticsearch credentials (username and password) with permissions to create and write to indices.

- Network connectivity from the Kubernetes cluster to the Elasticsearch endpoint.

## Vendor set up steps

### Step 1: Create Filebeat ConfigMap

Create a ConfigMap with Filebeat configuration in the `kube-system` namespace. Update the Elasticsearch host, username, and password in the configuration.

Save the following as `filebeat-cfgmap.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: filebeat-configmap
  namespace: kube-system
data:
  filebeat.yml: |
    filebeat.inputs:
      - type: filestream
        id: tetragon-log
        enabled: true
        paths:
          - /var/run/cilium/tetragon/*.log
    path.data: /usr/share/filebeat/data
    processors:
      - timestamp:
          field: "time"
          layouts:
            - '2006-01-02T15:04:05Z'
            - '2006-01-02T15:04:05.999Z'
            - '2006-01-02T15:04:05.999-07:00'
          test:
            - '2019-06-22T16:33:51Z'
            - '2019-11-18T04:59:51.123Z'
            - '2020-08-03T07:10:20.123456+02:00'
    setup.template.name: logs
    setup.template.pattern: "logs-cilium_tetragon.*"
    output.elasticsearch:
      hosts: ["https://<elasticsearch host>"]
      username: "<elasticsearch username>"
      password: "<elasticsearch password>"
      index: logs-cilium_tetragon.log-default
```

Apply the configuration:

```shell
kubectl create -f filebeat-cfgmap.yaml
```

### Step 2: Install Tetragon with Filebeat Sidecar

Create a Helm values file to configure Tetragon with a Filebeat sidecar for log export. Save the following as `filebeat-helm-values.yaml`:

```yaml
export:
  securityContext:
    runAsUser: 0
    runAsGroup: 0
  stdout:
    enabledCommand: false
    enabledArgs: false
    image:
      override: "docker.elastic.co/beats/filebeat:8.15.3"
    extraVolumeMounts:
      - name: filebeat-config
        mountPath: /usr/share/filebeat/filebeat.yml
        subPath: filebeat.yml
      - name: filebeat-data
        mountPath: /usr/share/filebeat/data
extraVolumes:
  - name: filebeat-data
    hostPath:
      path: /var/run/cilium/tetragon/filebeat
      type: DirectoryOrCreate
  - name: filebeat-config
    configMap:
      name: filebeat-configmap
      items:
        - key: filebeat.yml
          path: filebeat.yml
```

Install Tetragon using Helm:

```shell
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon -f filebeat-helm-values.yaml cilium/tetragon -n kube-system
```

### Step 3: Verify Deployment

Check the Tetragon DaemonSet status:

```shell
kubectl rollout status -n kube-system ds/tetragon -w
```

## Kibana set up steps

### Step 1: Install Integration Assets

1. In Kibana, navigate to **Management** > **Integrations**.

2. Search for "Cilium Tetragon" and select the integration.

3. Click **Add Cilium Tetragon Integration** or navigate to **Settings** > **Install Cilium Tetragon Integration**.

4. Choose **Add Integration Only** (skip Elastic Agent installation, as it is not supported for this integration).

5. Confirm the installation to load dashboards, visualizations, and index templates.

### Step 2: Verify Data Stream

1. Navigate to **Management** > **Index Management** > **Data Streams**.

2. Look for the `logs-cilium_tetragon.log-default` data stream.

3. Verify that documents are being ingested by checking the document count.

# Validation Steps

## Step 1: Verify Tetragon is Running

Check that Tetragon pods are running in the `kube-system` namespace:

```shell
kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon
```

All pods should be in `Running` status.

## Step 2: Verify Filebeat Sidecar

Check the logs of the Tetragon pod to ensure Filebeat is running and forwarding logs:

```shell
kubectl logs -n kube-system <tetragon-pod-name> -c export-stdout
```

Look for Filebeat startup messages and successful connections to Elasticsearch.

## Step 3: Check Data in Kibana Discover

1. In Kibana, navigate to **Discover**.

2. Select the `logs-cilium_tetragon.log-default` data view or create one if it doesn't exist.

3. Verify that events are appearing with recent timestamps.

4. Check that events contain expected fields such as:
   - `process_exec` or `process_exit` or `process_kprobe` data
   - Kubernetes metadata (pod name, namespace, container information)
   - Node name and cluster information

## Step 4: Generate Test Events

Trigger some activity in your Kubernetes cluster to generate events:

```shell
kubectl exec -it <any-pod> -- /bin/sh
```

Execute some commands within the pod and verify that corresponding process execution and exit events appear in Kibana within a few seconds.

## Step 5: Validate Event Types

Confirm that different event types are being collected:
- Process execution events with binary paths and arguments
- Process exit events with status codes
- Kernel probe events (if TracingPolicies are configured)

# Troubleshooting

## Common Configuration Issues

**Issue**: No data appearing in Elasticsearch after installation.

**Solutions**:
- Verify that the Filebeat ConfigMap was created successfully: `kubectl get configmap -n kube-system filebeat-configmap`
- Check Tetragon pod logs for errors: `kubectl logs -n kube-system <tetragon-pod-name>`
- Verify Filebeat sidecar is running: `kubectl logs -n kube-system <tetragon-pod-name> -c export-stdout`
- Confirm Elasticsearch credentials are correct in the ConfigMap
- Test network connectivity from Kubernetes cluster to Elasticsearch endpoint

**Issue**: Tetragon pods not starting or in CrashLoopBackOff state.

**Solutions**:
- Check pod events: `kubectl describe pod -n kube-system <tetragon-pod-name>`
- Verify kernel version supports eBPF: `uname -r` (kernel 4.9+ recommended, 5.3+ for full features)
- Check if required kernel modules are loaded
- Review Tetragon pod logs for specific error messages

**Issue**: Only some events are being collected, missing expected event types.

**Solutions**:
- Check the `tetragon.exportAllowList` and `tetragon.exportDenyList` Helm values in your deployment
- Update `filebeat-helm-values.yaml` to adjust event filtering:
  ```yaml
  tetragon:
    exportAllowList: "{\"event_set\":[\"PROCESS_EXEC\",\"PROCESS_EXIT\",\"PROCESS_KPROBE\"]}"
  ```
- Reinstall Tetragon with updated configuration

**Issue**: High volume of events causing performance issues.

**Solutions**:
- Configure event filtering using `exportDenyList` to exclude noisy events
- Filter by namespace to monitor only specific Kubernetes namespaces
- Adjust TracingPolicies to be more selective about which kernel functions are monitored
- Increase Filebeat buffer size in the ConfigMap if events are being dropped

## Ingestion Errors

**Issue**: Events appear in Elasticsearch with `error.message` field set.

**Solutions**:
- Check the error message details in the `error.message` field to identify parsing issues
- Verify that the Tetragon version is compatible with the integration's ingest pipeline
- Ensure the Filebeat timestamp processor configuration matches the Tetragon timestamp format
- Check for malformed JSON in Tetragon export logs

**Issue**: Missing or incorrect Kubernetes metadata in events.

**Solutions**:
- Verify Tetragon has proper RBAC permissions to access Kubernetes API
- Check if Tetragon is configured with correct cluster name: add `--cluster-name` flag in Helm values
- Ensure Tetragon pods have network access to Kubernetes API server

## API Authentication Errors

**Issue**: Filebeat cannot connect to Elasticsearch - authentication failures.

**Solutions**:
- Verify Elasticsearch credentials in the ConfigMap are correct
- Check if the Elasticsearch user has required permissions: `manage_index_templates`, `manage_ilm`, `write` on target indices
- Test credentials using curl from within a Tetragon pod
- If using Elastic Cloud, verify the cloud ID and API key format
- Check for TLS/SSL certificate issues if using self-signed certificates

**Issue**: Connection timeout or network errors connecting to Elasticsearch.

**Solutions**:
- Verify network connectivity: `kubectl exec -n kube-system <tetragon-pod-name> -c export-stdout -- curl -v <elasticsearch-url>`
- Check firewall rules between Kubernetes cluster and Elasticsearch
- Verify Elasticsearch endpoint URL is correct (including https:// protocol)
- Check for proxy settings that might be interfering with connections

## Vendor Resources

- [Tetragon Official Documentation](https://tetragon.io/docs/)
- [Tetragon Installation Guide](https://tetragon.io/docs/installation/kubernetes/)
- [Tetragon GitHub Repository - Issues](https://github.com/cilium/tetragon/issues)

# Documentation sites

- https://tetragon.io/docs/ - Official Tetragon documentation with installation, configuration, and usage guides
- https://tetragon.io/docs/installation/kubernetes/ - Kubernetes installation guide for Tetragon
- https://github.com/cilium/tetragon - Tetragon GitHub repository with source code and issue tracking
- https://www.elastic.co/guide/en/integrations/current/cilium_tetragon.html - Elastic's Cilium Tetragon integration documentation
