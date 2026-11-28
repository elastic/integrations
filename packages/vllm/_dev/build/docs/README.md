{{- generatedHeader }}
# vLLM Integration for Elastic

## Overview

The vLLM integration collects metrics from [vLLM](https://docs.vllm.ai), the open-source inference and serving engine for large language models. It shows how loaded each server is (running and waiting requests, KV cache usage, preemptions), how much work it does (prompt and generation tokens per second, finished requests by reason) and how fast it answers (time to first token, inter-token latency, end to end and queue time).

### Compatibility

This integration uses the metric names of the vLLM V1 engine, the only engine in current vLLM releases (`vllm:kv_cache_usage_perc`, `vllm:inter_token_latency_seconds`). Older releases that expose the V0 names `vllm:gpu_cache_usage_perc` and `vllm:time_per_output_token_seconds` are not mapped.

Kibana 9.2.0 or later is required, because the dashboard uses the ES|QL `TS` command.

### How it works

vLLM serves Prometheus metrics on the `/metrics` path of its OpenAI-compatible API server (port `8000` by default), with no extra flag. The Elastic Agent scrapes that endpoint with the Prometheus input and the ingest pipeline maps each metric to a field under `vllm.*`. The labels of each series (`model_name`, `engine` and, for finished requests, `finished_reason`) are kept under `vllm.labels.*`.

## What data does this integration collect?

The `metrics` data stream collects:

* **Scheduler state**: requests running and waiting, KV cache usage, preemptions.
* **Throughput**: prompt and generation tokens, prefix cache queries and hits, finished requests by `finished_reason` (`stop`, `length`, `abort`, `error`, `repetition`).
* **Latency histograms**: time to first token, inter-token latency, end to end latency, and the time each request spends in the waiting, running, prefill and decode phases.
* **Request size histograms**: prompt and generation tokens per request.

Other metrics exposed by vLLM are not collected by default. The **Metrics Filters Include** setting lists the metrics that are scraped.

### Supported use cases

* Find out when a server is saturated: the waiting queue grows, KV cache usage stays close to 100% and preemptions appear.
* Follow latency as users see it: time to first token for interactive use, inter-token latency for streaming.
* Compare models served on the same fleet by token throughput and finished requests, and spot clients giving up (`finished_reason: abort`).

## What do I need to use this integration?

* A vLLM server (`vllm serve`) reachable over HTTP from the Elastic Agent. If vLLM runs behind a proxy that requires authentication, set **Bearer Token File** and, for HTTPS, **SSL Configuration**.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Onboard / configure

1. In Kibana, go to **Management > Integrations** and add the **vLLM** integration.
2. Under **Hosts**, list the vLLM servers as `host:port`, for example `localhost:8000`.
3. Optionally change the collection **Period** (default `10s`).
4. Assign the integration to an Elastic Agent policy and deploy it.

When vLLM runs on Kubernetes, use [Kubernetes autodiscover](https://www.elastic.co/docs/reference/fleet/kubernetes-provider) conditions to scrape every vLLM pod, for example `${kubernetes.pod.ip}:8000`.

### Validation

Open the **[Metrics vLLM] Overview** dashboard and check that the panels show data. In **Discover**, filter on `data_stream.dataset: vllm.metrics` to see the documents.

## Troubleshooting

* No data: check that `curl http://<host>:8000/metrics` from the agent host returns lines that start with `vllm:`.
* Latency panels empty while the others have data: histograms are sent as the difference between two scrapes, so the first scrape after the agent starts has empty buckets, and a server that received no requests in the period has nothing to show.

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Performance and scaling

A vLLM server exposes a few hundred series for each served model. Each scrape produces one document for each combination of labels: one with the gauges, counters and histograms of the model, and one for each `finished_reason`.

## Reference

### Metrics

{{event "metrics"}}

{{fields "metrics"}}

### Inputs used

{{ inputDocs }}

## Additional resources

* [vLLM production metrics](https://docs.vllm.ai/en/latest/usage/metrics.html)
* [vLLM metrics design](https://docs.vllm.ai/en/latest/design/metrics.html)
