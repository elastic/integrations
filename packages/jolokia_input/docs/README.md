# Jolokia input

This input package collects metrics from  [Jolokia agents](https://jolokia.org/reference/html/agents.html) running on a target JMX server or dedicated proxy server.

The metrics are collected by communicating with a Jolokia HTTP/REST endpoint that exposes the JMX metrics over HTTP/REST/JSON.

The user can use this input for any service that collects metrics through Jolokia endpoint. User has the flexibility to provide custom mappings and custom ingets pipelines through the Kibana UI to get the tailored data. 

## Compatibility

The Jolokia module is tested with Jolokia 1.7.0.
