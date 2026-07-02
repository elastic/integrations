# Jaeger OpenTelemetry Input Package

## Overview
The Jaeger OpenTelemetry Input Package for Elastic collects traces in [Jaeger](https://www.jaegertracing.io/) format using the OpenTelemetry [jaegerreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/jaegerreceiver). Package variables map to that receiver’s configuration (which protocols to enable, listen addresses, TLS for gRPC and Thrift HTTP, and UDP tuning). Choose settings in Fleet when you add this integration.

**Source of truth for behavior:** Protocol support (gRPC, Thrift HTTP, Thrift UDP variants), default endpoints, TLS and UDP options, and how multiple protocols interact are defined upstream—not duplicated here. Read the official **[jaegerreceiver README](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/jaegerreceiver/README.md)** in OpenTelemetry Collector Contrib; for deeper detail use the receiver’s `config.go` in the same repository as described in the Elastic [OTel input packages](https://www.elastic.co/guide/en/integrations-developer/current/otel-input-packages.html) guide.

**Jaeger versus OTLP:** This input accepts **Jaeger-formatted** traces via the Jaeger receiver, not OTLP. For Jaeger product docs and migration notes, see [Jaeger documentation](https://www.jaegertracing.io/docs/).

**Compatibility / migration:** Many modern tracing SDKs and collectors prefer **OTLP** as the default export protocol, and some Jaeger-native components (especially legacy Thrift/agent-based paths) are being deprecated across the ecosystem. If your apps emit OTLP, use the `otlp_input_otel` package instead. If your apps emit Jaeger-native protocols (Jaeger gRPC or Thrift), this package is the right receiver. For background on the ecosystem shift, see OpenTelemetry’s “Migrating away from the Jaeger exporter in the Collector” post: https://opentelemetry.io/blog/2023/jaeger-exporter-collector-migration/

**Requirements:** Kibana 9.4.0 or later (traces support), Elastic Agent with Elastic Distribution of OpenTelemetry (EDOT).

### How it works
Fleet applies generated collector configuration so the **jaegerreceiver** in EDOT listens according to your policy and forwards traces through the agent pipeline to Elasticsearch.
