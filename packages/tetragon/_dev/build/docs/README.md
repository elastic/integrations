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

{{fields "log"}}