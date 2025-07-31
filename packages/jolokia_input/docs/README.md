# Jolokia input

This input package collects metrics from  [Jolokia agents](https://jolokia.org/agent.html) running on a target JMX server or dedicated proxy server.

The metrics are collected by communicating with a Jolokia HTTP/REST endpoint that exposes the JMX metrics over HTTP/REST/JSON.

The user can use this input for any service that collects metrics through Jolokia endpoint. User has the flexibility to provide custom mappings and custom ingets pipelines through the Kibana UI to get the tailored data. 

## Collect metrics from a Jolokia endpoint

To collect metrics from a Jolokia endpoint, configure the hosts setting to point to your Jolokia agent.
- supported path are `GET` and `POST`.
- Path specifies Jolokia endpoint and query params
    default path is `/jolokia`
    we can also add query parameters for example: `/jolokia/?ignoreErrors=true&canonicalNaming=false`

## JMX MBeans and attributes

The Jolokia Input package can collect metrics from various JMX MBeans by configuring the mbean parameter. You can specify which MBeans and attributes to collect using the following format:

```json
- mbean: 'java.lang:type=Runtime'
  attributes:
    - attr: Uptime
      field: uptime
- mbean: 'java.lang:type=Memory'
  attributes:
    - attr: HeapMemoryUsage
      field: memory.heap_usage
    - attr: NonHeapMemoryUsage
      field: memory.non_heap_usage
```

## Compatibility

The Jolokia module is tested with Jolokia 2.2.9.
