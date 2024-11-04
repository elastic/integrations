# Cilium Tetragon

## Overview

The **Cilium Tetragon** integration enables you to monitor and analyze events from [Tetragon](https://tetragon.io/), a Kubernetes-aware security observability and runtime enforcement tool supported by the CNCF. This integration provides insight into Tetragon's security event logs, allowing you to visualize data in Kibana, set up alerts, and quickly respond to security events within your Kubernetes environment.

## Datastreams

The Cilium Tetragon integration collects security event logs from Tetragon into a **logs** datastream in Elasticsearch.

## Requirements

To use the Cilium Tetragon integration, ensure the following:

- **Elastic Stack**: Elasticsearch and Kibana are required for data storage, search, and visualization. You can use the hosted **Elasticsearch Service on Elastic Cloud** (recommended) or deploy the Elastic Stack on your own hardware.
- **Kubernetes Environment**: Tetragon must be running in a Kubernetes cluster.

## Setup

### Step 1: Install Integration Assets

Before collecting data from Tetragon, install the required assets for this integration in Kibana:

1. In Kibana, navigate to **Settings** > **Install Cilium Tetragon Integration**.
2. Alternatively, go to **⊕ Add Cilium Tetragon** > **Add Integration Only** (skip Elastic Agent installation, which is unsupported for this integration).

### Step 2: Configure Tetragon for JSON Export

Tetragon needs to be configured to export its event data as JSON logs. You’ll then use **Filebeat** to send these logs to Elasticsearch. The simplest approach is to use the Tetragon Helm chart along with a Helm values file.

Refer to the [Tetragon Documentation](https://tetragon.io/docs/installation/kubernetes/) for general Helm installation guidance.

#### 2.1: Set Up Filebeat Config Map

First, create a ConfigMap with Filebeat configuration in the `kube-system` namespace. Update the Elasticsearch username and password in the provided configuration file.

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

To apply this configuration, run:

```shell
kubectl create -f filebeat-cfgmap.yaml
```

#### 2.2: Install Tetragon with Filebeat Sidecar

Next, install Tetragon with Helm, using an override file to configure a Filebeat sidecar to export logs. Save the following configuration as `filebeat-helm-values.yaml`:

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

Then, install Tetragon with:

```shell
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon -f filebeat-helm-values.yaml ${EXTRA_HELM_FLAGS[@]} cilium/tetragon -n kube-system
```

## Troubleshooting

If expected events are not appearing in Elasticsearch, ensure that Tetragon is configured to export the right events:

- Check the `tetragon.exportAllowList` and `tetragon.exportDenyList` Helm values. These can be adjusted by adding them to `filebeat-helm-values.yaml` to control which events are included in the JSON export.

## Reference

For additional guidance on installing or configuring Tetragon, visit the [Tetragon documentation](https://tetragon.io/docs/).

## Logs

### Log Datastream

The `log` datastream captures event logs from Tetragon. These events are indexed as `logs-cilium_tetragon.log-default` in Elasticsearch.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cilium_tetragon.log.cluster_name |  | keyword |
| cilium_tetragon.log.node_name |  | keyword |
| cilium_tetragon.log.process_exec.parent.auid |  | long |
| cilium_tetragon.log.process_exec.parent.docker |  | keyword |
| cilium_tetragon.log.process_exec.parent.exec_id |  | keyword |
| cilium_tetragon.log.process_exec.parent.flags |  | keyword |
| cilium_tetragon.log.process_exec.parent.parent_exec_id |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.container.id |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.container.image.id |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.container.image.name |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.container.name |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.container.pid |  | long |
| cilium_tetragon.log.process_exec.parent.pod.container.start_time |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.name |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.namespace |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.pod_labels.app.kubernetes.io/name |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.pod_labels.class |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.pod_labels.org |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.pod_labels.pod-template-hash |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.workload |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.workload_kind |  | keyword |
| cilium_tetragon.log.process_exec.parent.refcnt |  | long |
| cilium_tetragon.log.process_exec.parent.start_time |  | keyword |
| cilium_tetragon.log.process_exec.parent.tid |  | long |
| cilium_tetragon.log.process_exec.process.auid |  | long |
| cilium_tetragon.log.process_exec.process.docker |  | keyword |
| cilium_tetragon.log.process_exec.process.exec_id |  | keyword |
| cilium_tetragon.log.process_exec.process.flags |  | keyword |
| cilium_tetragon.log.process_exec.process.parent_exec_id |  | keyword |
| cilium_tetragon.log.process_exec.process.pod.container.image.id |  | keyword |
| cilium_tetragon.log.process_exec.process.pod.container.pid |  | long |
| cilium_tetragon.log.process_exec.process.pod.container.start_time |  | keyword |
| cilium_tetragon.log.process_exec.process.pod.name |  | keyword |
| cilium_tetragon.log.process_exec.process.pod.namespace |  | keyword |
| cilium_tetragon.log.process_exec.process.pod.pod_labels.app |  | keyword |
| cilium_tetragon.log.process_exec.process.pod.pod_labels.app.kubernetes.io/name |  | keyword |
| cilium_tetragon.log.process_exec.process.pod.pod_labels.class |  | keyword |
| cilium_tetragon.log.process_exec.process.pod.pod_labels.org |  | keyword |
| cilium_tetragon.log.process_exec.process.pod.pod_labels.pod-template-hash |  | keyword |
| cilium_tetragon.log.process_exec.process.pod.workload |  | keyword |
| cilium_tetragon.log.process_exec.process.pod.workload_kind |  | keyword |
| cilium_tetragon.log.process_exec.process.start_time |  | keyword |
| cilium_tetragon.log.process_exec.process.uid |  | long |
| cilium_tetragon.log.process_exit.parent.auid |  | long |
| cilium_tetragon.log.process_exit.parent.docker |  | keyword |
| cilium_tetragon.log.process_exit.parent.exec_id |  | keyword |
| cilium_tetragon.log.process_exit.parent.flags |  | keyword |
| cilium_tetragon.log.process_exit.parent.parent_exec_id |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.container.id |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.container.image.id |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.container.image.name |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.container.name |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.container.pid |  | long |
| cilium_tetragon.log.process_exit.parent.pod.container.start_time |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.name |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.namespace |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.pod_labels.app.kubernetes.io/name |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.pod_labels.class |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.pod_labels.org |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.pod_labels.pod-template-hash |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.workload |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.workload_kind |  | keyword |
| cilium_tetragon.log.process_exit.parent.refcnt |  | long |
| cilium_tetragon.log.process_exit.parent.start_time |  | keyword |
| cilium_tetragon.log.process_exit.parent.tid |  | long |
| cilium_tetragon.log.process_exit.process.auid |  | long |
| cilium_tetragon.log.process_exit.process.docker |  | keyword |
| cilium_tetragon.log.process_exit.process.exec_id |  | keyword |
| cilium_tetragon.log.process_exit.process.flags |  | keyword |
| cilium_tetragon.log.process_exit.process.parent_exec_id |  | keyword |
| cilium_tetragon.log.process_exit.process.pod.container.image.id |  | keyword |
| cilium_tetragon.log.process_exit.process.pod.container.pid |  | long |
| cilium_tetragon.log.process_exit.process.pod.container.start_time |  | keyword |
| cilium_tetragon.log.process_exit.process.pod.name |  | keyword |
| cilium_tetragon.log.process_exit.process.pod.namespace |  | keyword |
| cilium_tetragon.log.process_exit.process.pod.pod_labels.app.kubernetes.io/name |  | keyword |
| cilium_tetragon.log.process_exit.process.pod.pod_labels.class |  | keyword |
| cilium_tetragon.log.process_exit.process.pod.pod_labels.org |  | keyword |
| cilium_tetragon.log.process_exit.process.pod.pod_labels.pod-template-hash |  | keyword |
| cilium_tetragon.log.process_exit.process.pod.workload |  | keyword |
| cilium_tetragon.log.process_exit.process.pod.workload_kind |  | keyword |
| cilium_tetragon.log.process_exit.process.refcnt |  | long |
| cilium_tetragon.log.process_exit.process.start_time |  | keyword |
| cilium_tetragon.log.process_exit.process.uid |  | long |
| cilium_tetragon.log.process_exit.signal |  | keyword |
| cilium_tetragon.log.process_exit.status |  | float |
| cilium_tetragon.log.process_exit.time |  | keyword |
| cilium_tetragon.log.process_kprobe.action |  | keyword |
| cilium_tetragon.log.process_kprobe.args.capability_arg.name |  | keyword |
| cilium_tetragon.log.process_kprobe.args.capability_arg.value |  | long |
| cilium_tetragon.log.process_kprobe.args.file_arg.path |  | keyword |
| cilium_tetragon.log.process_kprobe.args.file_arg.permission |  | keyword |
| cilium_tetragon.log.process_kprobe.args.int_arg |  | long |
| cilium_tetragon.log.process_kprobe.args.user_ns_arg.gid |  | long |
| cilium_tetragon.log.process_kprobe.args.user_ns_arg.level |  | long |
| cilium_tetragon.log.process_kprobe.args.user_ns_arg.ns.inum |  | long |
| cilium_tetragon.log.process_kprobe.args.user_ns_arg.ns.is_host |  | boolean |
| cilium_tetragon.log.process_kprobe.args.user_ns_arg.uid |  | long |
| cilium_tetragon.log.process_kprobe.function_name |  | keyword |
| cilium_tetragon.log.process_kprobe.parent.auid |  | long |
| cilium_tetragon.log.process_kprobe.parent.docker |  | keyword |
| cilium_tetragon.log.process_kprobe.parent.flags |  | keyword |
| cilium_tetragon.log.process_kprobe.parent.parent_exec_id |  | keyword |
| cilium_tetragon.log.process_kprobe.parent.pod.container.id |  | keyword |
| cilium_tetragon.log.process_kprobe.parent.pod.container.image.id |  | keyword |
| cilium_tetragon.log.process_kprobe.parent.pod.container.image.name |  | keyword |
| cilium_tetragon.log.process_kprobe.parent.pod.container.name |  | keyword |
| cilium_tetragon.log.process_kprobe.parent.pod.container.pid |  | long |
| cilium_tetragon.log.process_kprobe.parent.pod.container.start_time |  | date |
| cilium_tetragon.log.process_kprobe.parent.pod.name |  | keyword |
| cilium_tetragon.log.process_kprobe.parent.pod.namespace |  | keyword |
| cilium_tetragon.log.process_kprobe.parent.pod.pod_labels.app.kubernetes.io/name |  | keyword |
| cilium_tetragon.log.process_kprobe.parent.pod.pod_labels.class |  | keyword |
| cilium_tetragon.log.process_kprobe.parent.pod.pod_labels.org |  | keyword |
| cilium_tetragon.log.process_kprobe.parent.pod.workload |  | keyword |
| cilium_tetragon.log.process_kprobe.parent.pod.workload_kind |  | keyword |
| cilium_tetragon.log.process_kprobe.parent.refcnt |  | long |
| cilium_tetragon.log.process_kprobe.policy_name |  | keyword |
| cilium_tetragon.log.process_kprobe.process.auid |  | long |
| cilium_tetragon.log.process_kprobe.process.docker |  | keyword |
| cilium_tetragon.log.process_kprobe.process.flags |  | keyword |
| cilium_tetragon.log.process_kprobe.process.ns.cgroup.inum |  | long |
| cilium_tetragon.log.process_kprobe.process.ns.ipc.inum |  | long |
| cilium_tetragon.log.process_kprobe.process.ns.mnt.inum |  | long |
| cilium_tetragon.log.process_kprobe.process.ns.net.inum |  | long |
| cilium_tetragon.log.process_kprobe.process.ns.pid.inum |  | long |
| cilium_tetragon.log.process_kprobe.process.ns.pid.pid_for_children.inum |  | long |
| cilium_tetragon.log.process_kprobe.process.ns.pid_for_children.inum |  | long |
| cilium_tetragon.log.process_kprobe.process.ns.time.inum |  | long |
| cilium_tetragon.log.process_kprobe.process.ns.time.is_host |  | boolean |
| cilium_tetragon.log.process_kprobe.process.ns.time.time_for_children.inum |  | long |
| cilium_tetragon.log.process_kprobe.process.ns.time.time_for_children.is_host |  | boolean |
| cilium_tetragon.log.process_kprobe.process.ns.time_for_children.inum |  | long |
| cilium_tetragon.log.process_kprobe.process.ns.time_for_children.is_host |  | boolean |
| cilium_tetragon.log.process_kprobe.process.ns.user.inum |  | long |
| cilium_tetragon.log.process_kprobe.process.ns.user.is_host |  | boolean |
| cilium_tetragon.log.process_kprobe.process.ns.uts.inum |  | long |
| cilium_tetragon.log.process_kprobe.process.parent_exec_id |  | keyword |
| cilium_tetragon.log.process_kprobe.process.pod.container.image.id |  | keyword |
| cilium_tetragon.log.process_kprobe.process.pod.container.pid |  | long |
| cilium_tetragon.log.process_kprobe.process.pod.container.start_time |  | date |
| cilium_tetragon.log.process_kprobe.process.pod.pod_labels.app.kubernetes.io/name |  | keyword |
| cilium_tetragon.log.process_kprobe.process.pod.pod_labels.class |  | keyword |
| cilium_tetragon.log.process_kprobe.process.pod.pod_labels.org |  | keyword |
| cilium_tetragon.log.process_kprobe.process.pod.workload |  | keyword |
| cilium_tetragon.log.process_kprobe.process.refcnt |  | long |
| cilium_tetragon.log.process_kprobe.return.int_arg |  | long |
| cilium_tetragon.log.process_kprobe.return_action |  | keyword |
| cilium_tetragon.log.time |  | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| container.labels | Image labels. | object |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.idxhi | The high-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.idxlo | The low-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.file.vol | The serial number of the volume that contains a file. (Windows-only) | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
