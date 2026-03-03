# Overview

[Universal Profiling](https://www.elastic.co/observability/universal-profiling) provides fleet-wide, whole-system, continuous profiling with zero instrumentation.

Get a comprehensive understanding of what lines of code are consuming compute resources throughout your entire fleet by visualizing your data in Kibana using the flamegraph, stacktraces, and top functions views.

## Requirements
* The workloads to be profiled must be running on Linux machines; with kernel >=4.15
* Elastic Cloud, version 8.7 or higher

## Key Features

### Frictionless Deployment
Powered by eBPF, Universal Profiling does not require any application source code changes, instrumentation, on-host debug symbols, or other intrusive operations. Just deploy the agent and receive profiling data a few minutes later.

### Always-on in Production
With extremely low overhead, Universal Profiling aims to stay within a budget of 1% of CPU usage and less than 250MB of RAM, meaning that for most workloads, even in production, it can run 24/7 with no noticeable impact on the profiled systems.

### Whole-System Visibility
Universal Profiling builds stack traces that go from the kernel, through userspace native code, all the way into code running in higher level runtimes, enabling unprecedented insight into your system’s behaviour at all levels.

### Heterogeneous Visibility
Universal Profiling even supports mixed-language stack traces. For example, Python or Java code calling native code and then calling into the kernel

The following language runtimes are supported: PHP, Python, Java (or any JVM language), Go, Rust, C/C++, Node.js/V8, Ruby, and Perl.

The minimum supported versions are:

* PHP: >= 7.3
* Python: >= 3.6
* JVM/JDK: >= 7
* V8: >= 8.1.0
* Ruby: >= 2.5
* Perl: >= 5.28

[Learn more](https://www.elastic.co/guide/en/observability/current/universal-profiling.html)
