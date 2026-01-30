# AGENTS.md - AI Agent Guidance for Elastic Integrations

This document provides essential context for AI agents working in the Elastic Integrations repository.

## Repository Overview

This repository contains sources for **Elastic Integrations** (Elastic Packages). Each package defines how to observe a specific product or service with the Elastic Stack, including:

- Configuration for the Elastic Agent
- Assets such as Kibana dashboards and Elasticsearch index templates
- Documentation about the package
- Tests to ensure functionality

Built packages are published to the [Elastic Package Registry](https://epr.elastic.co) and served to Fleet in Kibana.

## Key External Resources

- **Integrations Developer Guide**: https://www.elastic.co/guide/en/integrations-developer/current/index.html
- **Package Specification**: https://github.com/elastic/package-spec
- **elastic-package CLI**: https://github.com/elastic/elastic-package
- **Package Registry**: https://github.com/elastic/package-registry

## Repository Structure

```
integrations/
├── packages/                 # All integration packages (300+ packages)
│   └── <package>/
│       ├── manifest.yml      # Package metadata, owner, version, Kibana constraints
│       ├── changelog.yml     # Version history (newest entries on top)
│       ├── data_stream/      # Data stream definitions
│       │   └── <stream>/
│       │       ├── manifest.yml
│       │       ├── fields/           # Field definitions (fields.yml, ecs.yml, base-fields.yml)
│       │       ├── elasticsearch/    # Ingest pipelines
│       │       │   └── ingest_pipeline/
│       │       └── agent/            # Agent stream configs (.yml.hbs templates)
│       │           └── stream/
│       ├── _dev/             # Development assets
│       │   ├── build/        # Build configuration (build.yml, docs templates)
│       │   ├── deploy/       # Docker compose for local testing
│       │   └── test/         # Test configurations
│       ├── docs/             # Package documentation
│       ├── kibana/           # Kibana assets (dashboards, visualizations)
│       └── img/              # Icons and screenshots
├── docs/                     # Repository-wide documentation
│   └── extend/               # Extended developer documentation
├── .buildkite/               # CI pipeline configurations
├── dev/                      # Internal dev tools (Go utilities)
├── .github/CODEOWNERS        # Package ownership assignments
└── magefile.go               # Mage build targets
```

## Core Tool: elastic-package

The `elastic-package` CLI is essential for all development tasks. Key commands:

| Command | Description |
|---------|-------------|
| `elastic-package create package` | Scaffold a new integration package |
| `elastic-package create data-stream` | Add a new data stream to a package |
| `elastic-package check` | Run format, lint, and build together |
| `elastic-package build` | Build the package (outputs to `build/`) |
| `elastic-package lint` | Validate against package-spec |
| `elastic-package format` | Format package files (JSON, YAML) |
| `elastic-package stack up -d -v` | Start local Elastic Stack for testing |
| `elastic-package test` | Run tests (asset, pipeline, system, static, policy) |
| `elastic-package install` | Install package to Kibana |
| `elastic-package changelog` | Manage changelog entries |
| `elastic-package clean` | Clean build artifacts |

Commands with **package context** must be run from within a package directory (`packages/<name>/`).

## Package Manifest Structure

Key fields in `packages/<name>/manifest.yml`:

```yaml
format_version: 3.4.0           # Package format version
name: example                   # Package identifier (lowercase, underscores)
title: Example Integration      # Display title
version: "1.2.3"                # Semantic version (MUST be quoted)
description: Description here   # Package description
type: integration               # Package type
categories:
  - observability               # Package categories
conditions:
  kibana:
    version: "^8.15.0 || ^9.0.0"  # Kibana version constraint
owner:
  github: elastic/team-name     # GitHub team owner
  type: elastic                 # Owner type (elastic or partner)
policy_templates:               # Input configurations
  - name: example
    title: Example logs
    inputs:
      - type: logfile
        title: Collect logs
```

## Changelog Format

The `packages/<name>/changelog.yml` file tracks version history. **Newer versions go on top.**

```yaml
# newer versions go on top
- version: "1.2.3"
  changes:
    - description: Brief description of the change
      type: enhancement        # enhancement | bugfix | breaking-change
      link: https://github.com/elastic/integrations/pull/XXXXX
- version: "1.2.2"
  changes:
    - description: Previous change
      type: bugfix
      link: https://github.com/elastic/integrations/pull/XXXXX
```

**Versioning guidelines:**
- **Patch** (x.y.**Z**): Backward-compatible bug fixes
- **Minor** (x.**Y**.z): Backward-compatible new features
- **Major** (**X**.y.z): Breaking changes

## Testing

### Test Types

| Test Type | Description | Location |
|-----------|-------------|----------|
| **Static** | Validates fields, sample events, documentation | Automatic |
| **Pipeline** | Tests ingest pipelines with sample data | `_dev/test/pipeline/` |
| **System** | End-to-end tests with real data ingestion | `_dev/test/system/` |
| **Asset** | Validates ES/Kibana assets load correctly | Automatic |
| **Policy** | Tests policy configurations | `_dev/test/policy/` |

### Test File Locations

- Package-level tests: `packages/<name>/_dev/test/`
- Data stream tests: `packages/<name>/data_stream/<stream>/_dev/test/`

### Running Tests Locally

```bash
# Start the Elastic Stack
elastic-package stack up -d -v

# Navigate to the package
cd packages/<package-name>

# Run all tests
elastic-package test

# Run specific test type
elastic-package test pipeline
elastic-package test system
elastic-package test static
```

## Ingest Pipeline Development

**Location:** `packages/<name>/data_stream/<stream>/elasticsearch/ingest_pipeline/`

Ingest pipelines are YAML files that define Elasticsearch processors:

```yaml
description: Pipeline for processing logs
processors:
  - grok:
      field: message
      patterns:
        - '%{TIMESTAMP_ISO8601:@timestamp} %{LOGLEVEL:log.level} %{GREEDYDATA:message}'
  - rename:
      field: message
      target_field: event.original
      ignore_missing: true
  # Reference other pipelines using Mustache templating
  - pipeline:
      name: '{{ IngestPipeline "sub-pipeline" }}'
on_failure:
  - set:
      field: error.message
      value: '{{ _ingest.on_failure_message }}'
```

## Fields Definition

**Location:** `packages/<name>/data_stream/<stream>/fields/`

| File | Purpose |
|------|---------|
| `fields.yml` | Custom package-specific fields |
| `ecs.yml` | ECS field mappings |
| `base-fields.yml` | Common base fields |
| `agent.yml` | Agent-related fields |

### Field Properties

```yaml
- name: example.field
  type: keyword
  description: Description of the field
  metric_type: gauge          # For metrics: gauge or counter
  unit: byte                  # Units: byte, ms, percent, etc.
  dimension: true             # Mark as TSDB dimension
```

## CI/CD

### Pipelines

- **PR Tests**: https://buildkite.com/elastic/integrations (triggered on every PR)
- **Serverless Tests**: https://buildkite.com/elastic/integrations-serverless
- **Publishing**: https://buildkite.com/elastic/integrations-publish (auto on merge)
- **Daily/Weekly Jobs**: Run comprehensive tests across all packages

### Special PR Commands

Add these as comments on PRs:
- `/test` or `buildkite test this` - Trigger a new build
- `/test stack <version>` - Test with specific stack version (e.g., `/test stack 8.17.0`)
- `/test benchmark fullreport` - Generate full benchmark report

### CI Behavior

- Tests run only for packages with modified files
- If files outside `packages/` are modified, all packages are tested
- Packages are tested against their minimum supported Kibana version
- Container logs are uploaded to private Google Bucket for security

## Common Tasks

### Creating a New Package

```bash
cd packages/
elastic-package create package
# Follow prompts for: package type, name, version, license, etc.

cd <new-package>
elastic-package check
elastic-package create data-stream
```

### Adding a Changelog Entry

1. Edit `packages/<name>/changelog.yml`
2. Add new entry **at the TOP** of the file
3. Include description, type (`enhancement`/`bugfix`/`breaking-change`), and PR link

Or use the CLI:
```bash
elastic-package changelog add --description "Your change" --type enhancement --link "https://github.com/elastic/integrations/pull/XXXXX"
```

### Updating Package Version

1. Increment version in `packages/<name>/manifest.yml`
2. Add corresponding changelog entry
3. Run `elastic-package check` to validate

### Exporting Kibana Dashboards

```bash
elastic-package stack up -d -v
# Create/edit dashboards in Kibana UI
elastic-package export dashboards
```

### Bug Fix for Older Package Version

For hotfixes to previously released versions:
1. Use the backport pipeline: https://buildkite.com/elastic/integrations-backport
2. Follow the workflow in [docs/extend/developer-workflow-support-old-package.md](docs/extend/developer-workflow-support-old-package.md)

## Guidelines and Best Practices

### ECS Compliance
- Use Elastic Common Schema (ECS) fields where applicable
- Import ECS mappings via `_dev/build/build.yml`:
  ```yaml
  dependencies:
    ecs:
      reference: git@v8.6.0
      import_mappings: true
  ```

### Field Documentation
- Document ALL fields produced by the integration in `fields.yml`
- Use appropriate `metric_type` and `unit` for metric fields

### Logs
- Keep the original message field (`event.original`) for log integrations
- Make `preserve_original_event` user-configurable

### Documentation
- Follow [documentation guidelines](docs/extend/documentation-guidelines.md)
- Use `_dev/build/docs/README.md` for templated documentation with placeholders

### Dashboards
- Follow [dashboard guidelines](docs/extend/dashboard-guidelines.md)
- Use SVG format for logos, PNG for other images

## Important File Patterns

| Pattern | Description |
|---------|-------------|
| `packages/*/manifest.yml` | Package manifests |
| `packages/*/changelog.yml` | Package changelogs |
| `packages/*/data_stream/*/manifest.yml` | Data stream manifests |
| `packages/*/data_stream/*/elasticsearch/ingest_pipeline/*.yml` | Ingest pipelines |
| `packages/*/data_stream/*/fields/*.yml` | Field definitions |
| `packages/*/data_stream/*/_dev/test/` | Test configurations |
| `packages/*/_dev/build/build.yml` | Build configuration |
| `packages/*/_dev/build/docs/README.md` | Documentation template |
| `.github/CODEOWNERS` | Package ownership |

## CODEOWNERS

Package ownership is defined in [.github/CODEOWNERS](.github/CODEOWNERS).

- Each package has an assigned owner team (e.g., `@elastic/obs-infraobs-integrations`)
- The owner is also specified in the package's `manifest.yml` under `owner.github`
- Check ownership before making significant changes to unfamiliar packages
- Default owner for new packages: `@elastic/integrations-triaging`

## Package Types

There are different package types for different use cases. Understanding these types is essential when working in this repository.

### Integration Packages (`type: integration`)

Integration packages provide **complete monitoring solutions** for specific applications or services. They are the most common package type in this repository.

**Characteristics:**
- Configure multiple data streams and agent inputs
- Include dashboards, visualizations, and other Kibana assets
- Define field mappings using ECS (Elastic Common Schema)
- Include ingest pipelines for data processing
- Provide comprehensive documentation for the monitored service

**Structure:**
```
packages/<name>/
├── manifest.yml              # type: integration
├── changelog.yml
├── data_stream/              # One or more data streams
│   └── <stream>/
│       ├── manifest.yml
│       ├── fields/           # Field definitions (ECS)
│       ├── elasticsearch/    # Ingest pipelines
│       └── agent/stream/     # Agent stream configs
├── kibana/                   # Dashboards, visualizations
├── _dev/                     # Tests, build config
└── docs/
```

**Example:** The `apache` package includes configurations for access logs, error logs, and metrics, plus dashboards to visualize the data.

### Input Packages (`type: input`)

Input packages are intended for **generic use cases** where users need to collect custom data. They define how to configure an agent input that users can adapt to their specific needs.

**Characteristics:**
- Define a single, configurable input type
- No predefined data streams or field mappings
- Users provide their own processing and mapping
- More flexible but less "out-of-the-box" functionality

**Structure:**
```
packages/<name>/
├── manifest.yml              # type: input
├── changelog.yml
├── agent/input/              # Input configuration template
│   └── input.yml.hbs
├── _dev/
└── docs/
```

**Example:** The `log` input package lets users collect custom log files with their own parsing rules.

### Content Packages (`type: content`)

Content packages include **assets for the Elastic Stack** but don't define how to ingest data. They complement data collected by other means.

**Characteristics:**
- Include static data, dashboards, or other resources
- No agent input configuration
- Can use `discovery.datasets` for auto-installation when matching data arrives
- Often paired with input packages (e.g., `nginx_otel` content + `nginx_input_otel` input)

**Structure:**
```
packages/<name>/
├── manifest.yml              # type: content
├── changelog.yml
├── kibana/                   # Dashboards, visualizations
└── docs/
```

### Comparison Table

| Aspect | Integration | Input | Content |
|--------|-------------|-------|---------|
| `type` in manifest | `integration` | `input` | `content` |
| Data streams | Multiple | None | None |
| Field definitions | Yes (ECS) | No | No |
| Ingest pipelines | Yes | No | No |
| Kibana assets | Yes | No | Yes |
| Agent configuration | `data_stream/*/agent/` | `agent/input/` | None |
| Use case | Complete monitoring solution | Generic/custom data collection | Assets only |

### Choosing a Package Type

- **Need a complete solution for a service?** → Integration package
- **Need generic data collection users can customize?** → Input package  
- **Need dashboards/assets without data collection?** → Content package

For more details, see the [elastic-package documentation on package types](https://github.com/elastic/elastic-package/blob/main/docs/howto/package_types.md).

---

## OpenTelemetry (OTel) Input Packages

A special category of input packages that use the `otelcol` input type to configure OpenTelemetry Collector receivers.

### Examples in Repository

- `nginx_input_otel` - NGINX metrics via OTel nginxreceiver
- `httpcheck_otel` - HTTP endpoint monitoring via OTel httpcheckreceiver
- `filelog_otel` - File log collection via OTel filelogreceiver

### Key Differences from Standard Input Packages

| Aspect | Standard Input | OTel Input (`otelcol`) |
|--------|---------------|------------------------|
| Input type | `logfile`, `httpjson`, etc. | `input: otelcol` |
| Field schema | ECS (Elastic Common Schema) | OpenTelemetry Semantic Conventions |
| Agent config | Elastic Agent native inputs | OTel Collector receiver config |
| Categories | Various | Always includes `opentelemetry` |
| Kibana version | Varies | Requires `^9.2.0` or later |

### Manifest Structure

OTel input packages use `input: otelcol` in their policy templates:

```yaml
format_version: 3.5.0
name: example_otel
title: "Example OpenTelemetry Input"
version: 0.1.0
type: input
categories:
  - observability
  - opentelemetry              # Always include this category
conditions:
  kibana:
    version: "^9.2.0"          # OTel inputs require Kibana 9.2+
policy_templates:
  - name: examplereceiver
    type: metrics              # or "logs"
    title: Example OTel Input
    description: Collect data using OTel Collector
    input: otelcol             # Key differentiator
    template_path: input.yml.hbs
    vars:
      - name: endpoint
        type: text
        required: true
```

### Input Configuration Template

The input template defines an OTel Collector pipeline configuration:

```yaml
receivers:
  nginx:
    endpoint: {{endpoint}}
    collection_interval: {{collection_interval}}
processors:
  resourcedetection/system:
    detectors: ["system"]
service:
  pipelines:
    metrics:
      receivers: [nginx]
      processors: [resourcedetection/system]
```

Key points:
- Uses Handlebars templating (`{{variable}}`) for user-configurable values
- Defines OTel Collector `receivers`, `processors`, and `service.pipelines`
- Receiver names map to [OTel Collector contrib receivers](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver)

### Sample Event Structure

OTel input packages produce documents with a different structure than ECS-based packages:

```json
{
  "@timestamp": 1761653610755,
  "attributes": {
    "http.method": "GET",
    "http.status_class": "2xx",
    "http.url": "http://example.com"
  },
  "data_stream": {
    "dataset": "httpcheckreceiver.otel",
    "namespace": "default",
    "type": "metrics"
  },
  "metrics": {
    "httpcheck.status": 1
  },
  "scope": {
    "name": "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/httpcheckreceiver"
  }
}
```

Note: Uses `attributes` (following [OpenTelemetry Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/)) instead of ECS field paths, and a `metrics` object for metric values.

### Paired Content Packages

OTel input packages are often paired with content packages that provide dashboards:

- `nginx_input_otel` (input) + `nginx_otel` (content with dashboards)
- The content package uses `discovery.datasets` for auto-installation when matching data is ingested

## Environment Variables

Useful environment variables for `elastic-package`:

| Variable | Description |
|----------|-------------|
| `ELASTIC_PACKAGE_KIBANA_HOST` | Kibana host URL |
| `ELASTIC_PACKAGE_ELASTICSEARCH_HOST` | Elasticsearch host URL |
| `ELASTIC_PACKAGE_ELASTICSEARCH_USERNAME` | ES username |
| `ELASTIC_PACKAGE_ELASTICSEARCH_PASSWORD` | ES password |
| `STACK_VERSION` | Force specific stack version for testing |

Load stack environment after starting:
```bash
eval "$(elastic-package stack shellinit)"
```
