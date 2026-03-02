#!/usr/bin/env python3
"""
Generate and send traces in Jaeger Thrift HTTP format to the collector.
Used for system testing the jaeger_input_otel package.
Waits for SIGHUP from elastic-package (sent when agent is ready) before sending.
"""
import os
import signal
import time

from opentelemetry import trace
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

# Default endpoint for elastic-package system tests (elastic-agent is the Agent hostname)
DEFAULT_ENDPOINT = "http://elastic-agent:14268/api/traces"
ENDPOINT = os.environ.get("OTEL_EXPORTER_JAEGER_ENDPOINT", DEFAULT_ENDPOINT)

# Ensure format parameter is set for Jaeger Thrift
if "?" not in ENDPOINT:
    ENDPOINT = f"{ENDPOINT}?format=jaeger.thrift"

SERVICE_NAME_VALUE = os.environ.get("OTEL_SERVICE_NAME", "test-service")

agent_ready = False


def sighup_handler(signum, frame):
    global agent_ready
    agent_ready = True


def main():
    signal.signal(signal.SIGHUP, sighup_handler)
    print("Waiting for SIGHUP (agent ready signal)...")
    while not agent_ready:
        time.sleep(0.1)
    print("Agent ready, sending traces...")

    resource = Resource.create({SERVICE_NAME: SERVICE_NAME_VALUE})
    trace.set_tracer_provider(TracerProvider(resource=resource))

    jaeger_exporter = JaegerExporter(
        collector_endpoint=ENDPOINT,
    )
    span_processor = BatchSpanProcessor(jaeger_exporter)
    trace.get_tracer_provider().add_span_processor(span_processor)

    tracer = trace.get_tracer("jaeger-trace-sender", "1.0.0")

    print(f"Sending traces to {ENDPOINT}...")

    # Generate multiple traces with spans for reliable test data
    for i in range(5):
        with tracer.start_as_current_span(f"operation-{i}") as span:
            span.set_attribute("test.iteration", i)
            span.set_attribute("test.service", SERVICE_NAME_VALUE)
            with tracer.start_as_current_span("child-span"):
                time.sleep(0.1)

    # Force flush to ensure all spans are exported
    trace.get_tracer_provider().force_flush()
    trace.get_tracer_provider().shutdown()

    print("Traces sent successfully.")


if __name__ == "__main__":
    main()
