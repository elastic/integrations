# container-logs

container-logs integration collects and parses logs of Kubernetes containers.

It requires access to the log files in each Kubernetes node where the container logs are stored.
This defaults to `/var/log/containers/*${kubernetes.container.id}.log`.

By default, only {{ url "filebeat-input-filestream-parsers" "container parser" }} is enabled. Additional log parsers can be added as an advanced options configuration.

## Ingesting Rotated Container Logs
```{applies_to}
stack: beta 9.2.0
```

The integration can monitor and ingest rotated Kubernetes container logs, including 
on-the-fly decompression of GZIP archives. To enable this, `add gzip_experimental: true` 
under _Advanced options > Custom configurations_ and set the path to the rotated 
log files in the Kubernetes container log path configuration. Refer to
[filestream documentation on reading GZIP files](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-filestream#reading-gzip-files)

### Which path to add

Kubernetes stores logs on `/var/log/pods` and uses symlinks on `/var/log/containers`
for active log files. For full details, refer to the official 
[Kubernetes documentation on log rotation](https://kubernetes.io/docs/concepts/cluster-administration/logging/#log-rotation).

The path you add depends on whether this is a new or existing integration.

#### For new integrations

For new installations, instead of monitoring both paths, you can monitor only 
`/var/log/pods`, which includes active and rotated files.

Add the following path to the Kubernetes container log path configuration: 
`/var/log/pods/${kubernetes.namespace}_${kubernetes.pod.name}_${kubernetes.pod.uid}/${kubernetes.container.name}/*.log*`
This wildcard (`*.log*`) matches both active (`.log`) and rotated (`.log.*`) 
files.

#### For existing integrations
By default, existing integrations monitor active logs via `/var/log/containers`. 
To add rotated logs, you must add the path to the rotated log files:
`/var/log/pods/${kubernetes.namespace}_${kubernetes.pod.name}_${kubernetes.pod.uid}/${kubernetes.container.name}/*.log.*`

This wildcard (`*.log.*`) specifically targets only the rotated archive files.

::::{warning}
Potential Data Duplication: When you add this path to an existing integration, 
the integration reads all existing files in that directory from the beginning. 
This action causes a one-time re-ingestion of all previously rotated logs, which 
results in duplicate data.

After the initial scan, the integration tracks files normally and will only 
ingest new log data. Subsequent file rotations are handled correctly without 
further data duplication.
::::

## Rerouting and preserve original event based on pod annotations

You can customize the routing of container logs events and sending them to different datasets and namespaces,
as well as enable `preserve_original_event` based on using pods' annotations.

Customization can happen at:

- pod definition time, e.g., using a deployment.
- pod runtime, annotating pods using `kubectl`.

### Set at pod definition time

Here is an example of a Nginx deployment where we set both `elastic.co/dataset` and `elastic.co/namespace` annotations to route the container logs to specific datasets and namespace, respectively.

```yaml
# nginx-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      annotations:
        elastic.co/dataset: kubernetes.container_logs.nginx
        elastic.co/namespace: nginx
        elastic.co/preserve_original_event: "true"
      labels:
        app: nginx
        app.kubernetes.io/name: myservice
        app.kubernetes.io/version: v0.1.2
        app.kubernetes.io/instance: myservice-abcxzy
    spec:
      containers:
        - name: nginx-container
          image: nginx:latest
          ports:
            - containerPort: 80
```

### Set at runtime

Suppose you want to change the container logs routing and enable `preserve_original_event` on a running container.
In that case, you can annotate the pod using `kubectl`, and the integration will apply it immediately sending all the following documents to the new destination:

Here is an example where we route the container logs for a pod running the Elastic Agent to the `kubernetes.container_logs.agents` dataset:

```shell
kubectl annotate pods elastic-agent-managed-daemonset-6p22g elastic.co/dataset=kubernetes.container_logs.agents
```

Here's a similar example to change the namespace on a pod running Nginx:

```shell
kubectl annotate pods elastic-agent-managed-daemonset-6p22g elastic.co/namespace=nginx
```

Here is an example to enable `preserve_original_event` on a pod running Nginx:

```shell
kubectl annotate pods elastic-agent-managed-daemonset-6p22g elastic.co/preserve_original_event=true
```

You can restore the standard settings by removing the annotations:

```shell
kubectl annotate pods elastic-agent-managed-daemonset-6p22g elastic.co/dataset-
kubectl annotate pods elastic-agent-managed-daemonset-6p22g elastic.co/namespace-
kubectl annotate pods elastic-agent-managed-daemonset-6p22g elastic.co/preserve_original_event-
```

### Annotations Reference

Here are the annotations available to customize routing:

| Label                                | Description                                                                                    |
| ------------------------------------ | ---------------------------------------------------------------------------------------------- |
| `elastic.co/dataset`                 | Defines the target data stream's dataset for this pod.                                         |
| `elastic.co/namespace`               | Defines the target data stream's namespace for this pod.                                       |
| `elastic.co/preserve_original_event` | Enables 'preserve_original_event' for this pod. Use string 'true' (case-insensitive) to enable |
