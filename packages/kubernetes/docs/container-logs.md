# container-logs

container-logs integration collects and parses logs of Kubernetes containers.

It requires access to the log files in each Kubernetes node where the container logs are stored.
This defaults to `/var/log/containers/*${kubernetes.container.id}.log`.

By default only [container parser](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-filestream.html#_parsers) is enabled. Additional log parsers can be added as an advanced options configuration.


## Rerouting based on pod annotations

You can customize the routing of container logs events and sending them to different datasets and namespaces using pods' annotations.

Routing customization can happen at:

- pod definition time, e.g., using a deployment.
- pod runtime, annotating pods using `kubectl`.


### Set routing at pod definition time

Here is an example of an Nginx deployment where we set both `elastic.co/dataset` and `elastic.co/namespace` annotations to route the container logs to specific datasets and namespace, respectively.

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


### Set routing at runtime

Suppose you want to change the container logs routing on a running container. In that case, you can annotate the pod using `kubectl`, and the integration will apply it immediately sending all the following documents to the new destination:

Here is an example where we route the container logs for a pod running the Elastic Agent to the `kubernetes.container_logs.agents` dataset:

```shell
kubectl annotate pods elastic-agent-managed-daemonset-6p22g elastic.co/dataset=kubernetes.container_logs.agents
```

Here's a similar example to change the namespace on a pod running Nginx:

```shell
kubectl annotate pods elastic-agent-managed-daemonset-6p22g elastic.co/namespace=nginx
```

You can restore the standard routing by removing the annotations:

```shell
kubectl annotate pods elastic-agent-managed-daemonset-6p22g elastic.co/dataset-
kubectl annotate pods elastic-agent-managed-daemonset-6p22g elastic.co/namespace-
```

### Annotations Reference

Here are the annotations available to customize routing:


| Label                  | Description                                              |
| ---------------------- | -------------------------------------------------------- |
| `elastic.co/dataset`   | Defines the target data stream's dataset for this pod.   |
| `elastic.co/namespace` | Defines the target data stream's namespace for this pod. |
