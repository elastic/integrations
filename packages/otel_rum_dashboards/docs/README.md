{{- generatedHeader }}
{{/*
This template can be used as a starting point for writing documentation for your new integration. For each section, fill in the details
described in the comments.

Find more detailed documentation guidelines in https://www.elastic.co/docs/extend/integrations/documentation-guidelines
*/}}
# RUM OpenTelemetry Assets

## Overview

Use this package to get a dashboard which displays metrics from your web applications instrumented by Opentelemetry JS SDK.

### Compatibility

This package has ben tested with OpenTelemetry JS SDK `2.2.0` and with OpenTelemetry semantic conventions `1.38.0`. It should work with work with newer versions as long as there are no breaking changes in `browser.*` namespace.

## What do I need to use this integration?

This package will show metrics only if you are monitoring web applications with OpenTelemetry JS SDK. If you are new to OpenTelemetry RUM you can check the [guide](https://www.elastic.co/docs/solutions/observability/applications/otel-rum) on how to start with the Elastic stack.


### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **OpenTelemetry RUM JS**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

## Troubleshooting

If you do not see data in the dashboard make sure that:

- Elastic search has recevied the documents. You can search for the in discover with the filter `agent.name : "opentelemetry/webjs"`
- The `APM` data view is present. You can check for it in Stack Management -> Data Views