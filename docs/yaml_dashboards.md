---
mapped_pages: []
---

# YAML dashboards

YAML dashboards are an alternative way to define Kibana dashboards for integration packages. Instead of building dashboards in the Kibana UI and exporting JSON, you write a human-readable YAML file that compiles to integration package dashboard JSON.

YAML dashboards are particularly well-suited for LLM-assisted development. An LLM can generate, review, and iterate on a complete dashboard from a natural language description, something that isn't possible with the traditional point-and-click export workflow.

## How it works

A YAML dashboard file defines one or more dashboards using a structured schema. Then the compiler, `kb-dashboard`, converts these YAML definitions into dashboard JSON files that are stored in the package's `kibana/dashboard/` directory.

```text
packages/my_package/
  _dev/shared/kibana/       # YAML source files (not shipped)
    overview.yaml
    details.yaml
  kibana/dashboard/          # Compiled JSON (shipped with the package)
    my_package-overview.json
    my_package-details.json
```

The YAML source files live under `_dev/shared/kibana/` and are excluded from the shipped package. The compiled JSON files in `kibana/dashboard/` are what Kibana actually loads. Both must be committed to the repository. A CI workflow validates that the two stay in sync.

## When to use YAML dashboards

YAML dashboards work best for new dashboards, especially those using ES|QL or Lens visualizations. They are a good fit when:

- You are creating dashboards from scratch for a new integration.
- You want LLM assistance to generate or iterate on dashboards.
- You prefer version-controllable, diffable source files over opaque JSON.
- Your dashboards use ES|QL queries, Lens charts, or standard panel types (markdown, links, metrics, pie, XY, heatmap, gauge, datatable, tagcloud).

For existing integrations that already have JSON dashboards built through the Kibana UI, there is no requirement to migrate. The traditional export workflow described in [Create and export dashboards](/extend/create-dashboards.md) remains fully supported.

## Quick start

### 1. Install the compiler

The compiler is distributed as a Python package and runs using [uv](https://github.com/astral-sh/uv):

```bash
REQS=.github/workflows/validate-yaml-dashboards.requirements.txt

# Compile dashboards (no persistent install needed)
uvx --with-requirements "$REQS" --from kb-dashboard-cli==0.4.1 kb-dashboard compile --help

# Lint dashboards
uvx --with-requirements "$REQS" --from kb-dashboard-lint==0.4.1 kb-dashboard-lint check --help
```

The pinned package hashes live in `.github/workflows/validate-yaml-dashboards.requirements.txt`. Keep this file updated when bumping compiler versions.

If you are migrating older YAML dashboards from `0.2.7`, use the built-in upgrader first. It applies schema migrations automatically so you do not need to handle breaking changes by hand:

```bash
REQS=.github/workflows/validate-yaml-dashboards.requirements.txt

# Check if upgrades are needed (no files written)
uvx --with-requirements "$REQS" --from kb-dashboard-cli==0.4.1 kb-dashboard upgrade \
    --input-dir _dev/shared/kibana \
    --fail-on-change

# Apply upgrades in place
uvx --with-requirements "$REQS" --from kb-dashboard-cli==0.4.1 kb-dashboard upgrade \
    --input-dir _dev/shared/kibana \
    --write
```

### 2. Create a YAML dashboard file

Create a file under `packages/<your_package>/_dev/shared/kibana/`:

```yaml
---
dashboards:
  - id: my_package-overview
    name: "[Logs My Package] Overview"
    description: Overview of My Package logs
    filters:
      - field: data_stream.dataset
        equals: my_package.logs
    panels:
      - size: {w: 48, h: 4}
        markdown:
          content: |
            ## My Package Overview

      - title: Total Events
        size: {w: 12, h: 4}
        esql:
          type: metric
          query: |
            FROM logs-*
            | WHERE data_stream.dataset == "my_package.logs"
            | STATS total = COUNT(*)
          primary:
            field: total

      - title: Events Over Time
        size: {w: 36, h: 15}
        esql:
          type: bar
          query: |
            FROM logs-*
            | WHERE data_stream.dataset == "my_package.logs"
            | STATS event_count = COUNT(*)
              BY time_bucket = BUCKET(@timestamp, 20, ?_tstart, ?_tend)
            | SORT time_bucket ASC
          dimension:
            field: time_bucket
            data_type: date
          metrics:
            - field: event_count
```

### 3. Compile and lint

```bash
cd packages/my_package
REQS=../../.github/workflows/validate-yaml-dashboards.requirements.txt

# Lint the YAML
uvx --with-requirements "$REQS" --from kb-dashboard-lint==0.4.1 kb-dashboard-lint check \
    --input-file _dev/shared/kibana/overview.yaml

# Compile YAML to Elastic integration JSON
uvx --with-requirements "$REQS" --from kb-dashboard-cli==0.4.1 kb-dashboard compile \
    --input-dir _dev/shared/kibana \
    --output-dir kibana/dashboard \
    --format "elastic-integrations"
```

### 4. Commit both files

Commit both the YAML source and the compiled JSON. The CI workflow will verify they stay in sync on every PR.

## Using an LLM to create dashboards

YAML dashboards are designed to be LLM-friendly. The full schema documentation is available in a single file that can be loaded into an LLM context window.

### Providing context to the LLM

The compiler bundles all schema documentation, examples, and workflow guides. Use the `docs` subcommand to retrieve them:

```bash
# Output the complete documentation (schema, examples, style guides) to stdout
uvx --with-requirements .github/workflows/validate-yaml-dashboards.requirements.txt --from kb-dashboard-cli==0.4.1 kb-dashboard docs llms-full

# Copy to clipboard (macOS)
uvx --with-requirements .github/workflows/validate-yaml-dashboards.requirements.txt --from kb-dashboard-cli==0.4.1 kb-dashboard docs llms-full | pbcopy

# List available workflow guides
uvx --with-requirements .github/workflows/validate-yaml-dashboards.requirements.txt --from kb-dashboard-cli==0.4.1 kb-dashboard docs list-guides

# Output a specific guide
uvx --with-requirements .github/workflows/validate-yaml-dashboards.requirements.txt --from kb-dashboard-cli==0.4.1 kb-dashboard docs guide dashboard-style-guide
```

Feed the `llms-full` output to the LLM as context. It contains the full schema reference, panel type documentation, complete examples, and workflow guides. Run `kb-dashboard docs list-guides` to see all available guides. Currently bundled guides include:

- **dashboard-style-guide** -- layout hierarchy, naming conventions, visualization selection, and a checklist derived from analysis of 49 production dashboards
- **dashboard-decompiling-guide** -- step-by-step instructions for converting existing Kibana JSON dashboards to YAML, with component mapping tables and validation workflows
- **esql-language-reference** -- complete ES|QL syntax for dashboard queries, common mistakes to avoid, and dashboard query patterns for each chart type
- **otel-dashboard-guide** -- field path conventions, counter versus gauge metric patterns, and a validation checklist for OpenTelemetry receiver dashboards
- **breaking-changes** -- migration notes for schema changes between compiler versions
- **color-assignments** -- custom color assignment configuration for chart series
- **esql-views** -- reusable ES|QL query patterns using YAML anchors
- **legend-configuration** -- legend positioning and display options

If you are working on YAML dashboards you MUST read the llms-full and the guides `dashboard-style-guide`, `esql-language-reference`, and `otel-dashboard-guide`.

If you are converting existing JSON dashboards to YAML, you MUST read the llms-full and the guide `dashboard-decompiling-guide`.

### Prompting tips

When asking an LLM to create a dashboard, provide:

1. **The data you're visualizing.** Include the index pattern, relevant field names, and field types. If you have an existing `fields/` directory or ECS mappings, share those.

2. **What the dashboard should show.** Describe the panels you want: "show total event count, events over time broken down by status, and a top-10 table of source IPs."

3. **The schema reference.** Include the output of `kb-dashboard docs llms-full` for the LLM to reference.

4. **An example from this repo.** Point at an existing YAML dashboard such as `packages/aws_vpcflow_otel/_dev/shared/kibana/overview.yaml` as a concrete reference.

### Example prompt

> Create a YAML dashboard for the `my_package` integration. The data is in `logs-my_package.events-*` with fields: `@timestamp`, `event.action`, `event.outcome`, `source.ip`, `destination.ip`, `event.duration`.
>
> The dashboard should include:
>
> - A links panel for navigation
> - Metric panels for total events and unique source IPs
> - A time series bar chart of events over time, broken down by `event.outcome`
> - A pie chart of top 10 `event.action` values
> - A data table showing recent events
>
> Use ES|QL queries with dynamic time bucketing. Follow the schema in llms-full.txt and the style guide conventions for Elastic integrations dashboards.

### Iterating on the output

After the LLM produces a YAML file:

1. **Lint it** to catch schema issues:

   ```bash
   uvx --with-requirements .github/workflows/validate-yaml-dashboards.requirements.txt --from kb-dashboard-lint==0.4.1 kb-dashboard-lint check --input-file dashboard.yaml
   ```

2. **Compile it** to verify it produces valid integration JSON:

   ```bash
   uvx --with-requirements .github/workflows/validate-yaml-dashboards.requirements.txt --from kb-dashboard-cli==0.4.1 kb-dashboard compile \
       --input-file dashboard.yaml \
       --output-dir /tmp/output \
       --format "elastic-integrations"
   ```

3. If you have kibana running, you can **Upload it** to your running Kibana instance to visually verify:

   ```bash
   uvx --with-requirements .github/workflows/validate-yaml-dashboards.requirements.txt --from kb-dashboard-cli==0.4.1 kb-dashboard compile \
       --input-file dashboard.yaml \
       --upload \
       --kibana-url http://localhost:5601 \
       --kibana-username elastic \
       --kibana-password changeme
   ```

4. **Feed errors back** to the LLM. If linting or compilation fails, paste the error output back and ask the LLM to fix it.

## CI validation

A GitHub Actions workflow (`.github/workflows/validate-yaml-dashboards.yml`) runs on every PR that touches YAML dashboard sources or compiled JSON files. It:

1. **Lints** each changed YAML file for schema warnings and errors.
2. **Compiles** the YAML and checks that the output matches the committed JSON using the `--exit-non-zero-on-change` flag.

If the check fails, recompile locally and commit the updated JSON.

## Reference

- `kb-dashboard docs llms-full` -- complete schema reference, examples, and workflow guides (bundled with the compiler)
- `kb-dashboard docs list-guides` -- list all available workflow guides
- `kb-dashboard docs guide <name>` -- output a specific guide (for example `dashboard-style-guide`, `otel-dashboard-guide`)
