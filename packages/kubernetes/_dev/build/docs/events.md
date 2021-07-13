# events

## Metrics

### event

This is the `event` dataset of the Kubernetes package. It collects Kubernetes events
related metrics.

If Leader Election is activated (default behaviour) only the `elastic agent` which holds the leadership lock
will retrieve events related metrics.
This is relevant in multi-node kubernetes cluster and prevents duplicate data.

{{event "event"}}

{{fields "event"}}