---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/finishing-touches.html
---

# Finishing touches [finishing-touches]

## Words [_words]

Tips for manifest files:

* Descriptions of configuration options should be as short as possible.

    Remember to keep only the meaningful information about the configuration option.

    * Good candidates: references to the product configuration, accepted string values, explanation.
    * Bad candidates: Collect metrics from A, B, C, D,…​ X, Y, Z datasets.


* Descriptions should be human readable.

    Try to rephrase sentences like: Collect foo_Bar3 metrics, into Collect Foo Bar metrics.

* Descriptions should be easy to understand.

    Simplify sentences, don’t provide information about the input if not required.

    * Bad candidate: Collect application logs (log input)
    * Good candidates: Collect application logs, Collect standard logs for the application



## Add an icon [_add_an_icon]

The integration icons are displayed in different places in {{kib}}, hence it’s better to define custom icons to make the UI easier to navigate.


## Add screenshots [_add_screenshots]

The {{kib}} Integration Manager shows screenshots related to the integration. Screenshots include {{kib}} dashboards visualizing the metric and log data.


## Create a README file [_create_a_readme_file]

Every integration should include a README that helps users understand what the integration does, how to set it up, and what data it collects. The README is generated from a template file that supports dynamic content generation through template functions.

### README template location

The README template should be located at:

```
<package-name>/_dev/build/docs/README.md
```

::::{tip}
Packages created with `elastic-package create package` include a pre-populated README template that follows the [documentation guidelines](documentation-guidelines.md). This template includes placeholder text and comments to guide you through completing each section.
::::

### Building the README

After writing or updating your README template, run `elastic-package build` to generate the final README. The build process:

1. Processes all template functions in your template
2. Generates field tables, sample events, and other dynamic content
3. Outputs the final README to `docs/README.md`

The README should contain all sections defined in the [documentation guidelines](documentation-guidelines.md), including Overview, Setup, Troubleshooting, and Reference sections.

### Template functions [template-functions]

Template functions are placeholders in your README template that get replaced with generated content when you build the package. This ensures documentation stays in sync with your package's actual fields, sample events, and configuration.

The following template functions are available:

| Function | Description |
|----------|-------------|
| `{{ fields "data_stream_name" }}` | Generates a markdown table of all exported fields from the specified data stream's `fields/` directory. The table includes field names, descriptions, types, and metric types where applicable. If the data stream name is omitted, fields from the package root are used. |
| `{{ event "data_stream_name" }}` | Embeds the contents of `sample_event.json` from the specified data stream as a formatted JSON code block. This provides users with a concrete example of the data structure. |
| `{{ inputDocs }}` | Automatically lists all inputs used by the package (detected from data stream manifests) with their documentation rendered in collapsible sections. This helps users understand the available input configuration options. |
| `{{ url "link-id" "Caption" }}` | Generates a markdown link using predefined URLs from the [`links_table.yml`](https://github.com/elastic/elastic-package/blob/main/scripts/links_table.yml) file. Use this to link to Elastic documentation while ensuring links stay up-to-date. |
| `{{ generatedHeader }}` | Inserts a comment at the top of the file indicating it was auto-generated and should not be edited manually. This helps prevent accidental manual edits to the generated file. |
| `{{ alertRuleTemplates }}` | Lists any alert rule templates bundled with the package, including their names and descriptions. Only produces output if the package includes alert rule templates. |

**Example usage:**

```markdown
## Logs reference

{{ event "access" }}

{{ fields "access" }}
```

**Handling duplicate data stream names:**

If the same data stream name is used for both metrics and logs, differentiate them by adding `_logs` or `_metrics` suffixes to your data stream folder names. Then reference them accordingly in your template:

```markdown
{{ fields "elb_logs" }}
{{ fields "elb_metrics" }}
```

### AI-assisted documentation generation [ai-assisted-documentation]

As an alternative to writing the README template manually, `elastic-package update documentation` uses an LLM to generate documentation that follows the [documentation guidelines](documentation-guidelines.md).

To generate documentation for your integration, run:

```bash
elastic-package update documentation
```

::::{note}
This command requires a Gemini API key. Run `elastic-package update documentation --help` for details.
::::

The command reads package metadata and existing field definitions, then generates or updates the README template at `_dev/build/docs/README.md`. After running it, review the generated content, then run `elastic-package build` to produce the final `docs/README.md`.

An optional but recommended service info file can be added at:
```
<package-name>/docs/knowledge_base/service_info.md
```

The service info file is the authoritative source of information about the service. It provides the LLM with service-specific context used when generating the integration documentation. The tool draws on the information in this file, not its formatting or style — generated content will reflect the meaning described here but may not preserve exact phrasing.

The service info file should follow this template. All sections are optional:
```
# Service Info

## Common use cases
<Typical scenarios and goals that motivate use of this integration>

## Data types collected
<The types of data collected, the supported protocols, and the fields or information each data type contains>

## Compatibility
<Minimum or tested vendor product versions and any other compatibility requirements>

## Scaling and performance
<Known performance limits, resource requirements, and recommendations for optimizing throughput>

# Set up instructions

## Vendor prerequisites
<Required configuration or state of the vendor system before data collection can begin. For example, syslog configured with UDP output>

## Elastic prerequisites
<Required Elastic configuration before setting up this integration. For example, a deployment running Fleet or specific ports open on the Elastic Agent host>

## Vendor set up steps
<Steps required in the vendor product to establish the data flow to Elastic Agent. For example, configuring syslog to send data to the host running Elastic Agent>

### Vendor set up resources
<Vendor documentation or other resources relevant to configuring the data flow>

## Kibana set up steps
<Steps to install and configure the integration in Kibana>

# Validation steps
<Steps to confirm the integration is working correctly, including triggering data flow in the vendor product and verifying data arrives in Kibana>

# Troubleshooting
<Known issues and their solutions, organized under the appropriate subheading below>

## Common configuration issues

## Ingestion errors

## API authentication errors

# Documentation sites
<Vendor and third-party documentation that provides useful reference information about the service>

```

Using this command is optional — the manual authoring workflow described above remains fully supported.

### Documentation structure validation [documentation-structure-validation]

To ensure your README follows the recommended structure, you can enable documentation structure validation. When enabled, `elastic-package check` verifies that all required sections from the [documentation guidelines](documentation-guidelines.md) are present in your README.

To enable validation, add the following to your package's `validation.yml` file (create this file in your package root if it doesn't exist):

```yaml
docs_structure_enforced:
  enabled: true
  version: 1
```

**Skipping specific sections:**

If certain sections don't apply to your integration, you can skip validation for them by providing a reason:

```yaml
docs_structure_enforced:
  enabled: true
  version: 1
  skip:
    - title: "Performance and scaling"
      reason: "This integration has minimal resource requirements and doesn't require scaling guidance"
    - title: "API usage"
      reason: "This integration uses file-based input only"
```

::::{note}
Packages created with `elastic-package create package` have documentation structure validation enabled by default. The generated README template already includes all required sections, so validation should pass once you've filled in the placeholder content.
::::


## Review artifacts [_review_artifacts]



## Define variable properties [define-variable-properties]

The variable properties customize visualization of configuration options in the {{kib}} UI. Make sure they’re defined in all manifest files.

```yaml
vars:
  - name: paths
    required: true <1>
    show_user: true <2>
    title: Access log paths <3>
    description: Paths to the apache access log file. <4>
    type: text <5>
    multi: true <6>
    hide_in_deployment_modes: <7>
      - agentless
    default:
      - /var/log/httpd/access.log*
```

1. option is required
2. don’t hide the configuration option (collapsed menu)
3. human readable variable name
4. variable description (may contain some details)
5. field type (according to the reference: text, password, bool, integer)
6. the field has multiple values
7. hides the variable in agentless mode (see [`hide_in_deployment_modes`](/extend/define-deployment-modes.md#hide-in-deployment-modes) for more information)
