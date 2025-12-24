{{- generatedHeader }}
{{/*
This template can be used as a starting point for writing documentation for your new integration. For each section, fill in the details
described in the comments.

Find more detailed documentation guidelines in https://www.elastic.co/docs/extend/integrations/documentation-guidelines
*/}}
# OpenTelemetry RUM Integration for Elastic

## Overview

Use this instration to get a dashboard which displays metrics from your web applications instrumented by Opentelemetry JS SDK.

### Compatibility

This integration has ben tested with OpenTelemetry JS SDK `2.2.0` and with OpenTelemetry semantic conventions `1.38.0`. It should work with work with newer versions as long as there are no breaking changes in `browser.*` namespace.

## What do I need to use this integration?

This integration will show metrics only if you are monitoring web applications with OpenTelemetry JS SDK. If you are new to OpenTelemetry RUM you can check the [guide](https://www.elastic.co/docs/solutions/observability/applications/otel-rum) on how to start with the Elastic stack.


### Validation
{{/* How can the user test whether the integration is working? Including example commands or test files if applicable */}}

TODO

## Troubleshooting

TODO

### Inputs used
{{/* All inputs used by this package will be automatically listed here. */}}
{{ inputDocs }}
