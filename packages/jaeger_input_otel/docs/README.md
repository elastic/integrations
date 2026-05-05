# Jaeger OpenTelemetry Input Package

## Overview
The Jaeger OpenTelemetry Input Package for Elastic collects traces in [Jaeger](https://www.jaegertracing.io/) format using the OpenTelemetry [jaegerreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/jaegerreceiver). Package variables map to that receiver’s configuration (which protocols to enable, listen addresses, TLS for gRPC and Thrift HTTP, and UDP tuning); choose settings in Fleet when you add this integration.

**Source of truth for behavior:** Protocol support (gRPC, Thrift HTTP, Thrift UDP variants), default endpoints, TLS and UDP options, and how multiple protocols interact are defined upstream—not duplicated here. Read the official **[jaegerreceiver README](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/jaegerreceiver/README.md)** in OpenTelemetry Collector Contrib; for deeper detail use the receiver’s `config.go` in the same repository as described in the Elastic [OTel input packages](https://www.elastic.co/guide/en/integrations-developer/current/otel-input-packages.html) guide.

**Jaeger vs OTLP:** This input accepts **Jaeger-formatted** traces via the Jaeger receiver, not OTLP. For Jaeger product docs and migration notes, see [Jaeger documentation](https://www.jaegertracing.io/docs/).

**Requirements:** Kibana 9.4.0 or later (traces support), Elastic Agent with Elastic Distribution of OpenTelemetry (EDOT).

### How it works
Fleet applies generated collector configuration so the **jaegerreceiver** in EDOT listens according to your policy and forwards traces through the agent pipeline to Elasticsearch.
