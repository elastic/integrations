---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/otel-input-packages.html
---

# OTel Input Packages [otel-input-packages]

OTel Input Packages are **input-type packages** (`type: input`) that configure OpenTelemetry Collector receivers within EDOT (Elastic Distribution of OpenTelemetry). Unlike traditional integrations with data streams, these packages define Handlebars templates that generate OTel Collector configuration, allowing data to flow directly through the OTel pipeline to Elasticsearch.

## When to Create an OTel Input Package [when-to-create]

Use **OTel Input Packages** for [OpenTelemetry Collector receivers](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver). Use **traditional [integrations](./what-is-an-integration.md)** for Beats-based data collection.

## Development Workflow [development-workflow]

Follow this workflow when creating a new OTel Input Package:

### 1. Research the Upstream Receiver

Find your receiver in the [opentelemetry-collector-contrib receivers](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver):

- **README.md** — Configuration options, defaults, data types collected
- **config.go** — Complete configuration structure and Go types
- **metadata.yaml** — Available metrics (if applicable)

### 2. Define Variables

Map upstream configuration to [manifest variables](#variable-types):

| Upstream Go Type | Package Variable Type |
|------------------|----------------------|
| `string` | `text` |
| `string` (secret) | `password` (with `secret: false`) |
| `bool` | `bool` |
| `time.Duration` | `duration` |
| `[]string` | `text` with `multi: true` |
| Complex structs | `yaml` |
| Enum values | `select` |

Set `show_user: true` for commonly configured options, `show_user: false` for advanced settings.

### 3. Build the Template

Create `agent/input/input.yml.hbs` following the [Template Development](#template-dev) patterns:

- Mirror the upstream YAML structure
- Use `{{#if var}}` for optional fields, but emit booleans directly
- Include the `resourcedetection/system` processor

### 4. Write Documentation

Follow the [Documentation guidelines](./documentation-guidelines.md). For OTel packages, link to upstream receiver docs rather than duplicating configuration details.

### 5. Add Tests

- **Policy tests** — Refer to [Policy testing](./policy-testing.md). Cover default and non-default configurations.
- **System tests** — Refer to [System Testing Guide](./system-testing.md). Set up Docker infrastructure for live data flow testing.

### 6. Finalize

Run `elastic-package format` and `elastic-package check`, then verify the [Submission Checklist](#submission-checklist).

## Package Structure [package-structure]

OTel Input Packages follow the standard [input package](./integration-definitions.md#_input_package) structure with specific naming and configuration requirements.

```
packages/<name>_input_otel/
├── manifest.yml              # Package metadata and configuration
├── changelog.yml             # Version history
├── LICENSE.txt               # Optional: License file
├── docs/
│   └── README.md             # User-facing documentation
├── img/
│   └── <logo>.svg            # Package icon (32x32 recommended)
├── agent/
│   └── input/
│       └── input.yml.hbs     # OTel Collector template
├── sample_event.json         # Optional: Example event (generated via tests)
└── _dev/
    ├── deploy/
    │   └── docker/           # Service deployment for tests
    │       └── docker-compose.yml
    └── test/
        ├── policy/           # Policy tests (required)
        │   ├── test-default.yml
        │   └── test-default.expected
        └── system/           # System tests (recommended)
            └── test-default-config.yml
```

## Manifest Configuration [manifest-config]

The `manifest.yml` file defines your package metadata and configurable variables. For the complete manifest specification, refer to [manifest.yml](./manifest-spec.md). Here's an annotated example based on the StatsD input package:

```yaml
format_version: 3.5.0
name: statsd_input_otel
title: "StatsD OpenTelemetry Input Package"
version: 0.1.0
source:
  license: "Elastic-2.0"
description: "StatsD OpenTelemetry Input Package"
type: input                    # Must be "input" for OTel packages
categories:
  - observability
  - opentelemetry              # Always include this category
  - custom                     # Add relevant categories
conditions:
  kibana:
    version: "^9.2.0"          # OTel support requires Kibana 9.2.0+
  elastic:
    subscription: "basic"
icons:
  - src: /img/statsd_otellogo.svg
    title: StatsD OTel logo
    size: 32x32
    type: image/svg+xml
policy_templates:
  - name: statsdreceiver       # Usually matches the OTel receiver name
    type: metrics              # or "logs" depending on data type
    title: StatsD OpenTelemetry Input
    description: Collect StatsD metrics using OpenTelemetry Collector
    input: otelcol             # Required: specifies OTel Collector input
    template_path: input.yml.hbs
    vars:
      # Define configurable variables here
      - name: endpoint
        type: text
        required: true
        title: Endpoint
        description: Address and port to listen on for StatsD metrics.
        default: localhost:8125
owner:
  github: elastic/ecosystem   # Your team
  type: elastic
```

### Variable Types [variable-types]

OTel Input Packages support these variable types:

| Type | Description | Example |
|------|-------------|---------|
| `text` | Free-form text input | Endpoints, paths |
| `password` | Sensitive text (masked in UI) | Credentials |
| `bool` | Boolean toggle | Feature flags |
| `duration` | Time duration with unit | `60s`, `5m` |
| `select` | Dropdown with predefined options | Protocol selection |
| `yaml` | Multi-line YAML configuration | Advanced settings |

**Important:** For `password` fields, use `secret: false` as a workaround until [fleet-server#6277](https://github.com/elastic/fleet-server/issues/6277) is resolved.

### Variable Options [variable-options]

```yaml
vars:
  - name: transport
    type: select
    required: false
    title: Transport Protocol
    default: udp
    show_user: false           # Hide from basic UI
    options:
      - text: UDP
        value: udp
      - text: TCP
        value: tcp

  - name: aggregation_interval
    type: duration             # Use duration for time intervals
    required: false
    title: Aggregation Interval
    default: 60s

  - name: targets
    type: text
    multi: true                # Allow multiple values
    default:
      - localhost:9090
```

## Template Development [template-dev]

The `input.yml.hbs` file is a Handlebars template that generates OTel Collector configuration.

### Basic Structure [basic-structure]

```handlebars
receivers:
  <receiver-name>:
    endpoint: {{endpoint}}
    {{#if optional_setting}}
    optional_setting: {{optional_setting}}
    {{/if}}
processors:
  resourcedetection/system:
    detectors: ["system"]
service:
  pipelines:
    metrics:                   # or "logs" for log data
      receivers: [<receiver-name>]
      processors: [resourcedetection/system]
```

### Handlebars Patterns [handlebars-patterns]

**Conditional fields with defaults:**
```handlebars
{{#if transport}}
transport: {{transport}}
{{/if}}
```

**Boolean fields:** Boolean fields with `default: false` should NOT use `{{#if}}` wrappers because Handlebars evaluates `false` as falsy:
```handlebars
# Correct: Always output boolean values directly
enable_metric_type: {{enable_metric_type}}
is_monotonic_counter: {{is_monotonic_counter}}
```

**Iterating over multi-value fields:**
```handlebars
static_configs:
  - targets:
{{#each targets}}
      - {{this}}
{{/each}}
```

**Embedding YAML configuration:**
```handlebars
processors:
  resourcedetection:
    detectors: ["system"]
    system: {{system_config}}
```

### Resource Detection Processor [resource-detection]

Always include the `resourcedetection` processor for host enrichment:

```handlebars
processors:
  resourcedetection/system:
    detectors: ["system"]
```

For more detailed host information, use a YAML variable:

```handlebars
processors:
  resourcedetection:
    detectors: ["system"]
    system: {{system_config}}
```

With a default value in the manifest:
```yaml
- name: system_config
  type: yaml
  default: |
    hostname_sources: ["os"]
    resource_attributes:
      host.name:
        enabled: true
      host.arch:
        enabled: true
```

## Testing [testing]

OTel Input Packages require policy tests and should include system tests. For a complete overview of all test types, refer to [Test an integration](./testing.md).

### Policy Tests [policy-tests]

Policy tests verify that the package configuration generates valid Elastic Agent policies. For complete details on policy testing, refer to [Policy testing](./policy-testing.md).

**Required files:**
- `_dev/test/policy/test-default.yml` - Test input values
- `_dev/test/policy/test-default.expected` - Expected output

**Example `test-default.yml`:**
```yaml
vars:
  endpoint: "localhost:8125"
  transport: udp
  aggregation_interval: 60s
  enable_metric_type: false
  is_monotonic_counter: false
```

### System Tests [system-tests]

System tests validate the complete data flow from your service to Elasticsearch. For complete details on system testing, including deployment methods and troubleshooting, refer to [System Testing Guide](./system-testing.md).

**Required files:**
- `_dev/deploy/docker/docker-compose.yml` - Service deployment
- `_dev/test/system/test-default-config.yml` - Test configuration

**Example `test-default-config.yml`:**
```yaml
service_notify_signal: SIGHUP
vars:
  endpoint: "0.0.0.0:8125"
assert:
  hit_count: 6                 # Expected number of documents
```

::::{note}
There is currently a known [bug](https://github.com/elastic/elastic-package/issues/3275) where Datasets in generated sample files do not match with the expected files in test policies. This mismatch is expected behavior for now.
::::

## Documentation [documentation]

Create a `_dev/build/docs/README.md` template following the [Documentation guidelines](./documentation-guidelines.md). The template is rendered to `docs/README.md` when you run `elastic-package build`. For OTel Input Packages, include:

1. **Overview** - What the package does and which OTel receiver it uses
2. **How it works** - Data flow explanation
3. **Configuration** - Link to upstream receiver documentation
4. **Metrics/Logs reference** - Link to upstream documentation

**Example structure:**
```markdown
# <Package Name> OpenTelemetry Input Package

## Overview
The <Package Name> OpenTelemetry Input Package enables collection of <data type>
using the [<receiver-name>](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/<receiver>).

## How it works
This package configures the <receiver-name> in the EDOT collector, which
forwards data to Elastic Agent for processing and indexing in Elasticsearch.

## Configuration
For the full list of settings, refer to the upstream
[configuration documentation](https://github.com/open-telemetry/...).

## Metrics reference
For available metrics, refer to the [<receiver> documentation](https://github.com/open-telemetry/...).
```

## Package Icon [package-icon]

Create a combined logo that represents both the product and OpenTelemetry:
- Format: SVG
- Size: 32x32 pixels recommended
- Location: `img/<name>_otellogo.svg`

Refer to these existing icons as examples:
- [hostmetrics_input_otel/img/system-otel.svg](https://github.com/elastic/integrations/blob/main/packages/hostmetrics_input_otel/img/system-otel.svg)
- [iis_input_otel/img/iis_otellogo.svg](https://github.com/elastic/integrations/blob/main/packages/iis_input_otel/img/iis_otellogo.svg)

## Submission Checklist [submission-checklist]

Before submitting your OTel Input Package:

- [ ] `manifest.yml` has `type: input` and `input: otelcol`
- [ ] `manifest.yml` includes `opentelemetry` in categories
- [ ] `manifest.yml` has `conditions.kibana.version: "^9.2.0"` or newer
- [ ] `input.yml.hbs` includes `resourcedetection` processor
- [ ] Policy tests exist and pass (`_dev/test/policy/`)
- [ ] System tests exist and pass (`_dev/test/system/`)
- [ ] `sample_event.json` is generated from system tests (use `elastic-package test system --generate`)
- [ ] `_dev/build/docs/README.md` template exists; `docs/README.md` is rendered by `elastic-package build`
- [ ] `changelog.yml` has an entry for the initial version
- [ ] Package icon exists in `img/`
- [ ] `CODEOWNERS` file includes your team for the package path
- [ ] Run `elastic-package format` to ensure all YAML files are formatted as expected

## Examples [examples]

Reference these existing packages as examples, or search for packages containing `_input_otel` in the [packages directory](https://github.com/elastic/integrations/tree/main/packages):

| Package | Complexity | Notable Features |
|---------|------------|------------------|
| [statsd_input_otel](https://github.com/elastic/integrations/tree/main/packages/statsd_input_otel) | Basic | Minimal configuration, good starting point |
| [prometheus_input_otel](https://github.com/elastic/integrations/tree/main/packages/prometheus_input_otel) | Medium | TLS config, authentication, multi-value fields |
| [kafka_input_otel](https://github.com/elastic/integrations/tree/main/packages/kafka_input_otel) | Medium | Kafka receiver; system tests use telemetrygen + OTel Collector to produce OTLP into Kafka |
| [hostmetrics_input_otel](https://github.com/elastic/integrations/tree/main/packages/hostmetrics_input_otel) | Complex | Conditional scrapers, YAML configuration |

## Additional Resources [resources]

**Internal documentation:**
- [Test an integration](./testing.md) - Overview of all test types
- [Policy testing](./policy-testing.md) - Policy test details
- [System Testing Guide](./system-testing.md) - System test details
- [Documentation guidelines](./documentation-guidelines.md) - Writing integration docs
- [manifest.yml](./manifest-spec.md) - Complete manifest specification
- [Input Package Definition](./integration-definitions.md#_input_package) - Input package concepts

**External resources:**
- [OpenTelemetry Collector Receivers](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver)
- [elastic-package Policy Testing HOWTO](https://github.com/elastic/elastic-package/blob/main/docs/howto/policy_testing.md)
- [elastic-package System Testing HOWTO](https://github.com/elastic/elastic-package/blob/main/docs/howto/system_testing.md)
