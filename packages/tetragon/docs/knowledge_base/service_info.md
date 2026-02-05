# Service Info

The Cilium Tetragon integration provides deep runtime security observability and enforcement for Kubernetes workloads using eBPF technology. It allows users to monitor kernel-level events and system calls in real-time.

## Common use cases

The Cilium Tetragon integration is designed to provide deep runtime security observability and enforcement for Kubernetes workloads using eBPF technology. By ingesting Tetragon's JSON event logs, security teams can gain granular visibility into the internal workings of their clusters.

- **Runtime Security Monitoring:** Detect and alert on suspicious process executions, such as unauthorized shells or privilege escalation attempts within containers.
- **Network Observability:** Monitor socket-level activities and network connections at the kernel level to identify potential data exfiltration or command-and-control (C2) communication.
- **Compliance Auditing:** Maintain a tamper-evident audit log of system calls and file integrity events required for regulatory frameworks like PCI-DSS, SOC2, or HIPAA.
- **Vulnerability Response:** Quickly identify which containers are running specific processes or accessing sensitive files when a new zero-day vulnerability is announced.

## Data types collected

This integration can collect the following types of data:
- **Security Event Logs:** Comprehensive runtime security events from the Tetragon agent.
- **Process Metadata:** Detailed information regarding process execution, including binary paths, PIDs, and parent-child relationships.
- **Network Logs:** Connectivity data including source/destination IPs, ports, and protocol-specific details for cluster traffic.
- **System Call Information:** Detailed logs of system calls monitored by Tetragon's eBPF-based enforcement engine.

## Compatibility

This integration is compatible with **Cilium Tetragon** running in Kubernetes environments. The integration has been specifically tested and validated using a sidecar deployment pattern.

## Scaling and Performance

To ensure optimal performance in high-volume Kubernetes environments, consider the following:

- **Transport/Collection Considerations:** This integration utilizes the **filestream** input via a Filebeat sidecar. Reading logs directly from a shared volume within the pod ensures low-latency access and avoids the network overhead associated with external syslog collection. The sidecar approach ensures that log collection scales naturally and linearly with the number of Tetragon pods in the cluster.
- **Data Volume Management:** To manage high volumes of security data, it is recommended to configure the `tetragon.exportAllowList` and `tetragon.exportDenyList` values. Filtering at the source (the Tetragon engine) prevents ingesting unnecessary system events, reduces disk I/O, and minimizes the processing load on the Elasticsearch cluster.

# Set Up Instructions

## Vendor prerequisites

1. **Kubernetes Cluster:** A running Kubernetes cluster where you have permissions to deploy DaemonSets and ConfigMaps in the `kube-system` namespace.
2. **Helm Package Manager:** Helm v3 installed and configured locally to manage the Tetragon deployment.
3. **Administrative Access:** `kubectl` access with `cluster-admin` or equivalent permissions to create RBAC resources and security contexts.
4. **Security Context Permissions:** Tetragon requires the ability to run containers with `privileged: true` or specific capabilities (`CAP_SYS_ADMIN`), and the Filebeat sidecar requires `runAsUser: 0`.

## Elastic prerequisites

- **Integration Assets:** The Cilium Tetragon integration assets must be installed in Kibana via the Integrations app before data ingestion begins.
- **Network Connectivity:** Kubernetes nodes must have outbound network connectivity to the Elasticsearch cluster (typically port `443` or `9200`).
- **Elastic Agent not supported:** Note that the standard Elastic Agent is not supported for this specific sidecar-based integration. Instead, data is collected by deploying Filebeat as a sidecar container within the Tetragon DaemonSet.

## Vendor set up steps

### For Kubernetes Sidecar Collection:

1. **Install Integration Assets in Kibana:** 
   Navigate to **Management > Integrations** in Kibana. Search for **Cilium Tetragon** and select **Add Cilium Tetragon**. Click **Add Integration Only** (skip Elastic Agent installation) to load the necessary templates and pipelines without enrolling an agent.

2. **Create the Filebeat ConfigMap:**
   Create a file named `filebeat-config.yaml` to define how the sidecar should process logs. Use the following structure, replacing the Elasticsearch host and credentials with your own:
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
   Apply it with: `kubectl apply -f filebeat-config.yaml`.

3. **Configure Tetragon Helm Values:**
   Create a `filebeat-helm-values.yaml` file to enable JSON export and inject the sidecar container. Ensure filebeat image version matches your Elastic stack version.
   ```yaml
   export:
     securityContext:
       runAsUser: 0
       runAsGroup: 0
     stdout:
       enabledCommand: false
       enabledArgs: false
       image:
         override: "docker.elastic.co/beats/filebeat:9.3.0"
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

4. **Deploy Tetragon:**
   Add the Cilium Helm repo and install the chart with your override file:
   ```bash
   helm repo add cilium https://helm.cilium.io
   helm repo update
   helm install tetragon -f filebeat-helm-values.yaml ${EXTRA_HELM_FLAGS[@]} cilium/tetragon -n kube-system
   ```

### Vendor Set up Resources

- [Tetragon | Deploy on Kubernetes](https://tetragon.io/docs/installation/kubernetes/) - Describes how to install Tetragon on Kubernetes using Helm.
- [Tetragon Concepts: Events & JSON Export](https://tetragon.io/docs/concepts/events/) - Detailed explanation of how Tetragon generates and formats events.
- [Tetragon Helm Chart Reference](https://tetragon.io/docs/reference/helm-chart/) - Comprehensive list of Helm values for customizing the deployment.

## Kibana set up steps

### log
The **log** input (type: `filestream`) is used to collect Tetragon security events from the local filesystem where the eBPF engine exports logs.

1. In Kibana, navigate to **Management > Integrations**.
2. Search for and select **Cilium Tetragon**.
3. Click **Add Cilium Tetragon**.
4. Follow the prompts to install the integration assets. **Important:** Because this integration uses a Filebeat sidecar, do not use the "Add Elastic Agent" flow. Select **Add Integration Only** to install dashboards and pipelines.
5. Configure the general integration settings:
   - **Integration Name**: A unique name for this integration instance (e.g., `tetragon-kubernetes`).
   - **Namespace**: The namespace where data will be indexed (e.g., `default`).
6. Note that this input does not have UI-configurable variables in the Kibana interface. All log paths and processing logic are defined in the Filebeat sidecar `filebeat.yml` within your Kubernetes ConfigMap.
7. Click **Save and continue**.

# Validation Steps

After configuration is complete, verify that data is flowing correctly.

### 1. Trigger Data Flow on Tetragon:
Perform an action which will trigger a Tetragon event. The action required to trigger an alert will depend on your configured Tetragon policies. Some common actions are:
- **Generate process execution event:** Run a command inside any pod in your cluster: `kubectl exec -it <pod-name> -- ls /etc`.
- **Trigger a privileged action:** Attempt to access a sensitive file or run a command as root within a container.

### 2. Check Data in Kibana:
1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the KQL filter: `data_stream.dataset : "tetragon.log"`
4. Verify logs appear. Expand a log entry and confirm these fields:
   - `event.dataset` (should be `tetragon.log`)
   - `kubernetes.pod.name`
5. Navigate to **Analytics > Dashboards** and search for "Cilium Tetragon" to view the pre-built dashboards.

# Troubleshooting

## Common Configuration Issues

- **Volume Mount Mismatch**: Ensure the `exportDirectory` in the Tetragon configuration matches the `mountPath` in both the Tetragon container and the Filebeat sidecar container. If these do not align, Filebeat will find an empty directory.
- **RBAC and Permissions**: If the Filebeat sidecar fails to start, verify that the `securityContext` is set to `runAsUser: 0`. Filebeat often requires root permissions to read logs from host-mounted or shared volumes in Kubernetes.

## Ingestion Errors

- **Timestamp Format Mismatch**: Tetragon may export timestamps in various layouts. If you see `mapper_parsing_exception` in the Elastic logs, verify that the `timestamp` processor in your Filebeat ConfigMap includes the correct layouts (e.g., `2006-01-02T15:04:05.999Z`).
- **Empty Events**: Check the `tetragon.exportAllowList` and `tetragon.exportDenyList` Helm values. These can be adjusted by adding them to filebeat-helm-values.yaml to control which events are included in the JSON export.

## Vendor Resources

- [Tetragon Troubleshooting](https://tetragon.io/docs/troubleshooting/)

# Documentation sites

- [Official Tetragon Documentation](https://tetragon.io/docs/)
- [Tetragon Kubernetes Installation](https://tetragon.io/docs/installation/kubernetes/)
