# Kubelet Stats OpenTelemetry Input Package

## Overview

The Kubelet Stats OpenTelemetry Input Package for Elastic enables collection of Kubernetes node, pod, container, and volume metrics from the Kubelet API using the [kubeletstatsreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/kubeletstatsreceiver).

This package collects metrics directly from the Kubelet's `/stats/summary` endpoint, providing detailed resource usage information for Kubernetes workloads.

### How it works

This package configures the Kubelet Stats receiver in the EDOT (Elastic Distribution of OpenTelemetry) collector to scrape metrics from the Kubelet API. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis.

## What data does this integration collect?

This integration collects metrics about Kubernetes resources:

| Metric Group | Description |
|-------------|-------------|
| Node | CPU, memory, filesystem, and network metrics for the node |
| Pod | CPU, memory, filesystem, and network metrics for pods |
| Container | CPU, memory, filesystem metrics for containers |
| Volume | Capacity and usage metrics for volumes |

Key metrics include:

| Metric Name | Description | Type |
|-------------|-------------|------|
| k8s.node.cpu.utilization | Node CPU utilization | Gauge |
| k8s.node.memory.usage | Node memory usage in bytes | Gauge |
| k8s.pod.cpu.utilization | Pod CPU utilization | Gauge |
| k8s.pod.memory.usage | Pod memory usage in bytes | Gauge |
| k8s.container.cpu.utilization | Container CPU utilization | Gauge |
| k8s.container.memory.usage | Container memory usage in bytes | Gauge |
| k8s.volume.capacity | Volume capacity in bytes | Gauge |
| k8s.volume.available | Volume available space in bytes | Gauge |

## Configuration

### Authentication Types

The receiver supports multiple authentication methods:

- **serviceAccount** (default): Uses the service account token mounted in the pod. Recommended for in-cluster deployments.
- **tls**: Uses TLS client certificates for authentication.
- **kubeConfig**: Uses a kubeconfig file for authentication.
- **none**: No authentication (uses read-only port 10255).

### Required Permissions

When using `serviceAccount` authentication, the service account needs appropriate RBAC permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kubelet-stats-reader
rules:
- apiGroups: [""]
  resources: ["nodes/stats"]
  verbs: ["get"]
```

### Sample Configuration

Basic configuration with service account authentication:

- **Endpoint**: `https://localhost:10250`
- **Auth Type**: `serviceAccount`
- **Collection Interval**: `10s`

For TLS authentication:

- **Endpoint**: `https://localhost:10250`
- **Auth Type**: `tls`
- **CA File**: `/path/to/ca.crt`
- **Cert File**: `/path/to/client.crt`
- **Key File**: `/path/to/client.key`

## Troubleshooting

### Common Issues

**Connection refused errors:**
- Verify the Kubelet endpoint is accessible from the collector
- Check that the correct port is being used (10250 for secure, 10255 for read-only)
- Ensure RBAC permissions are correctly configured

**Certificate errors:**
- When using TLS auth, verify certificate paths are correct
- Consider enabling `insecure_skip_verify` for testing (not recommended for production)
- Ensure the CA file matches the Kubelet's certificate

**Empty metrics:**
- Verify `metric_groups` includes the desired metric types
- Check Kubelet logs for any errors
- Ensure the node name is correctly configured if using node utilization metrics

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Reference

### Metrics Reference

For a complete list of all available metrics and their detailed descriptions, refer to the [Kubelet Stats Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/kubeletstatsreceiver/documentation.md) in the upstream OpenTelemetry Collector repository.

### Inputs Used

This package uses the [Kubelet Stats Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/kubeletstatsreceiver) of the OTel Collector.
