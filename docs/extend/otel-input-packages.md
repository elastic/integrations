---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/otel-input-packages.html
---

# OTel Input Packages [otel-input-packages]

OTel Input Packages are **input-type packages** (`type: input`) that configure OpenTelemetry Collector receivers within EDOT (Elastic Distribution of OpenTelemetry). Unlike traditional integrations with data streams, these packages define Handlebars templates that generate OTel Collector configuration, allowing data to flow directly through the OTel pipeline to Elasticsearch.

## When to Create an OTel Input Package [when-to-create]

Use **OTel Input Packages** for [OpenTelemetry Collector receivers](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver). Use **traditional [integrations](./what-is-an-integration.md)** for Beats-based data collection.

## Development Workflow [development-workflow]

Follow this step-by-step workflow when creating a new OTel Input Package. This ensures consistent, high-quality packages that align with existing patterns.

### Step 1: Research the Upstream Receiver [step-1-research]

Before writing any code, thoroughly understand the OTel receiver you're wrapping:

1. **Find the receiver documentation**: Navigate to the [opentelemetry-collector-contrib receivers directory](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver) and locate your receiver (e.g., `statsdreceiver`, `prometheusreceiver`).

2. **Read the README.md**: Review the receiver's README to understand:
   - What data types it collects (metrics, logs, traces)
   - Required vs optional configuration options
   - Default values for all settings
   - Any special behaviors or limitations

3. **Examine the config.go file**: Look at the receiver's `config.go` for the complete configuration structure. This reveals all possible options and their Go types.

4. **Check for related documentation**: Some receivers have additional docs (e.g., metric documentation files listing all available metrics).

### Step 2: Identify Configurable Variables [step-2-variables]

From your research, determine which configuration options should be exposed to users:

1. **Always expose essential settings**: Options like `endpoint`, collection intervals, or authentication are typically required.

2. **Evaluate optional settings**: For each optional setting, ask:
   - Does a typical user need to change this?
   - Is the default appropriate for most use cases?
   - Does exposing this add unnecessary complexity?

3. **Group by user visibility**:
   - `show_user: true` — Common settings users frequently configure
   - `show_user: false` — Advanced settings most users can ignore

4. **Map upstream types to package variable types**:

   | Upstream Go Type | Package Variable Type | Notes |
   |------------------|----------------------|-------|
   | `string` | `text` | For endpoints, paths, names |
   | `string` (secret) | `password` | For credentials (use `secret: false` for now) |
   | `bool` | `bool` | For feature toggles |
   | `time.Duration` | `duration` | For intervals like `60s`, `5m` |
   | `[]string` | `text` with `multi: true` | For lists of values |
   | Complex structs | `yaml` | For advanced nested configuration |
   | Enum/limited values | `select` | For protocol choices, modes |

### Step 3: Create the Input Template [step-3-template]

Build your `input.yml.hbs` template based on the upstream receiver configuration:

1. **Start with the receiver section**: Mirror the upstream YAML structure exactly.

2. **Add conditional wrappers**: Use `{{#if variable}}` for optional fields that shouldn't appear when empty.

3. **Handle booleans carefully**: Emit boolean values directly (not wrapped in `{{#if}}`) to ensure `false` values are included.

4. **Match upstream defaults**: When a variable has a default in your manifest that matches the upstream default, consider whether you need to emit it.

5. **Include resource detection**: Add the `resourcedetection` processor to enrich data with host information.

6. **Define the service pipeline**: Connect receivers and processors in the appropriate pipeline (metrics, logs, or traces).

### Step 4: Write the Documentation [step-4-docs]

Create user-facing documentation that helps users understand and configure the package:

1. **Overview section**: Explain what the package does and link to the upstream receiver.

2. **How it works**: Describe the data flow from source through OTel to Elasticsearch.

3. **Configuration reference**: Either document key settings inline or link directly to upstream documentation for the complete list.

4. **Data reference**: Link to upstream docs for metrics/logs documentation rather than duplicating.

5. **Troubleshooting**: Add common issues specific to the receiver (e.g., platform requirements, firewall considerations).

### Step 5: Test the Package [step-5-test]

Validate your package works correctly:

1. **Create policy tests**: Add test cases in `_dev/test/policy/` covering:
   - Default configuration
   - Non-default values for key settings
   - Edge cases (empty optional fields, multiple values)

2. **Set up system tests**: Create `_dev/deploy/docker/` infrastructure to test live data flow. If the receiver only works on specific platforms (e.g., Windows), document this limitation.

3. **Run tests locally**:
   ```bash
   elastic-package test policy -v
   elastic-package test system -v
   ```

4. **Generate expected files**: Use `elastic-package test policy --generate` to create `.expected` files after verifying output is correct.

### Step 6: Finalize and Submit [step-6-submit]

Complete the package and prepare for submission:

1. **Format all files**: Run `elastic-package format` to ensure consistent YAML formatting.

2. **Add CODEOWNERS entry**: Add your team to `.github/CODEOWNERS` for the package path.

3. **Create package icon**: Design an SVG that represents both the source technology and OpenTelemetry.

4. **Review the submission checklist**: Verify all items in the [Submission Checklist](#submission-checklist) are complete.

5. **Validate the package**: Run `elastic-package check` to catch any specification violations.

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

Create a `docs/README.md` following the [Documentation guidelines](./documentation-guidelines.md). For OTel Input Packages, include:

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

## Submission Checklist [submission-checklist]

Before submitting your OTel Input Package:

- [ ] `manifest.yml` has `type: input` and `input: otelcol`
- [ ] `manifest.yml` includes `opentelemetry` in categories
- [ ] `manifest.yml` has `conditions.kibana.version: "^9.2.0"` or newer
- [ ] `input.yml.hbs` includes `resourcedetection` processor
- [ ] Policy tests exist and pass (`_dev/test/policy/`)
- [ ] System tests exist and pass (`_dev/test/system/`)
- [ ] `docs/README.md` documents the package
- [ ] `changelog.yml` has an entry for the initial version
- [ ] Package icon exists in `img/`
- [ ] `CODEOWNERS` file includes your team for the package path
- [ ] Run `elastic-package format` to ensure all YAML files are formatted as expected

## Examples [examples]

Reference these existing packages as examples, or search for packages containing `_input_otel` in the [packages directory](https://github.com/elastic/integrations/tree/main/packages):

| Package | Complexity | Notable Features |
|---------|------------|------------------|
| [statsd_input_otel](https://github.com/elastic/integrations/tree/main/packages/statsd_input_otel) | Simple | Minimal configuration, good starting point |
| [prometheus_input_otel](https://github.com/elastic/integrations/tree/main/packages/prometheus_input_otel) | Medium | TLS config, authentication, multi-value fields |
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
