# Golang Integration

## Overview

The Golang integration allows you to monitor a [Golang](https://go.dev/) application. Go is a statically typed, compiled programming language designed at Google. It is syntactically similar to C, but with memory safety, garbage collection, structural typing, and CSP-style concurrency. It is often referred to as Golang.

Use the Golang integration to:
- Gain insights into expvar and heap statistics.
- Create visualizations to monitor, measure and analyze the state of heap, garbage collector, memory, mcache structures, mspan structures etc.

## Data streams

The Golang integration collects metrics using [expvar](https://pkg.go.dev/expvar) package. Metrics are exported on "/debug/vars" endpoint after [importing](https://pkg.go.dev/expvar#:~:text=into%20your%20program%3A-,import%20_%20%22expvar%22,-Index%20%C2%B6) expvar package and adding an HTTP handler.

**Logs** help you keep a record of state of Golang application.
Log data streams collected by the Golang integration include [expvar](https://pkg.go.dev/expvar) and [Heap](https://go.dev/src/runtime/mstats.go#:~:text=118%20119%20%2F%2F%20HeapAlloc%20is%20bytes%20of%20allocated%20heap%20objects.).

Data streams:
- `heap`:  Collects heap metrics like heap allocation and garbage collection metrics.
- `expvar`: Collects metrics like memstats, cmdline and custom (user-defined) metrics.

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

### expvar

This is the `expvar` data stream. Metrics of garbage collector, mcache structures and mspan structures can be collected using `expvar` data stream. Custom metrics can also be collected under `golang.expvar.custom` field.

{{event "expvar"}}

{{fields "expvar"}}

### Heap

This is the `heap` data stream. Metrics like heap allocations and GC pause can be collected using `heap` data stream.

{{event "heap"}}

{{fields "heap"}}
