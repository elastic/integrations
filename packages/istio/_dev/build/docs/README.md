# Istio Integration

This integration ingest access logs and metrics created by the [Istio](https://istio.io/) service mesh.

## Compatibility

The Istio datasets were tested with Istio 1.14.3.

## Logs

### Access Logs

The `access_logs` data stream collects Istio access logs.

{{event "access_logs"}}

{{fields "access_logs"}}


## Metrics

### Istiod Metrics

The `istiod_metrics` data stream collects Istiod metrics.

{{event "istiod_metrics"}}

{{fields "istiod_metrics"}}

### Proxy Metrics

The `proxy_metrics` data stream collects Istio proxy metrics.

{{event "proxy_metrics"}}

{{fields "proxy_metrics"}}