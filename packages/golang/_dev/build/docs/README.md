# Golang Integration

## Overview

The Golang integration allows you to monitor a [Golang](https://go.dev/) application. Go is a statically typed, compiled programming language designed at Google. It is syntactically similar to C, but with memory safety, garbage collection, structural typing, and CSP-style concurrency. It is often referred to as Golang.

Use the Golang integration to:
- Gain insights into heap statistics.
- Create visualizations to monitor, measure and analyze the state of heap.

## Data streams

The Golang integration collects metrics using [expvar](https://pkg.go.dev/expvar) package. Metrics are exported on "/debug/vars" endpoint after [importing](https://pkg.go.dev/expvar#:~:text=into%20your%20program%3A-,import%20_%20%22expvar%22,-Index%20%C2%B6) expvar package and adding an HTTP handler.

**Logs** help you keep a record of state of Golang application.
Log data streams collected by the Golang integration include [Heap](https://go.dev/src/runtime/mstats.go#:~:text=118%20119%20%2F%2F%20HeapAlloc%20is%20bytes%20of%20allocated%20heap%20objects.).

Data streams:
- `heap`:  Collects heap metrics like heap allocation and garbage collection metrics.

Note: 
- Users can monitor and see the metrics inside the ingested documents for Golang in the `logs-*` index pattern from `Discover`.

## Compatibility

This integration has been tested against Golang versions `1.19` and `1.18`.

## Prerequisites

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your own hardware.

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Logs reference

### Heap

This is the `heap` data stream. Metrics like heap allocations and GC pause can be collected using `heap` data stream.

Note: 
- Field with name "last_num_gc" is added in the raw response which can be seen in event.original field if the `Preserve original event` toggle is enabled, this field is used to process metrics related to GC pause and does not occur in actual response.
- Fields `golang.heap.gc.pause.avg.ns`, `golang.heap.gc.pause.count`, `golang.heap.gc.pause.max.ns` and `golang.heap.gc.pause.sum.ns` are derived from `PauseNs` metric which is an array of size 256. After exceeding array size values are [overwritten](https://go.dev/src/runtime/mstats.go#:~:text=PauseNs%20is%20a,during%20a%20cycle.) from the start. In a case where the collection period is very long there is a chance that the array is overwritten multiple times. In this case, some GC cycles can be missed.
- Fields `golang.heap.gc.pause.avg.ns`, `golang.heap.gc.pause.count`, `golang.heap.gc.pause.max.ns` and `golang.heap.gc.pause.sum.ns` are calculated from second last document if filebeat ever restarts.

{{event "heap"}}

{{fields "heap"}}