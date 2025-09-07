# **Comprehensive Guide — Building an Elastic Integration from a REST API**

> **Audience:** LLM-based CLI agents with shell and `elastic-package` access.
> **Goal:** Generate a complete Elastic integration (v0.1.0) that ingests REST API data, passes all `elastic-package test` runners, and installs cleanly into Kibana.

---

## 🧰 0. Prerequisites

Assumed pre-satisfied:

* `elastic-package` in `$PATH`
* Clean Git repo for the package
* Running Elasticsearch/Kibana stack
* Valid `task.md` with:

  * API base URLs, auth, endpoints, examples
  * Dataset name(s), field descriptions
  * Request/response samples

---

## 📌 1. Understand the API Task (`task.md`)

### Parse and extract:

| Element              | Purpose                                                  |
| -------------------- | -------------------------------------------------------- |
| Base URL / Endpoints | Compose `resource.url` in agent template                 |
| Auth method          | Needed for `auth.*` fields in stream config              |
| Sample responses     | Turn into `sample_event.json`, test fixtures             |
| Business fields      | Map to ECS (`event.id`, `@timestamp`, `rule.name`, etc.) |
| Required variables   | Populate `vars` in `manifest.yml`                        |

> 💡 **Tip**: Use a script or regex to extract and temporarily store raw JSON samples for reuse.

---

## 📦 2. Create the Integration Package

```bash
elastic-package create package
```

### Wizard prompts:

| Prompt            | Example                            |
| ----------------- | ---------------------------------- |
| Type              | integration                        |
| Name              | `my_api` (snake\_case)             |
| Version           | 0.1.0                              |
| Title/Desc/Cats   | From `task.md`                     |
| Kibana constraint | Match stack version (e.g. ^8.13.0) |

### Directory layout:

```
my_api/
├── changelog.yml
├── manifest.yml
├── data_stream/
└── _dev/
    └── build/
```

---

## 🌊 3. Create the Data Stream

```bash
cd my_api
elastic-package create data-stream
```

| Prompt           | Example             |
| ---------------- | ------------------- |
| Data stream name | `api`               |
| Type             | `logs` or `metrics` |

Result:

```
data_stream/api/
├── manifest.yml
├── agent/stream/
├── elasticsearch/ingest_pipeline/
├── fields/
├── sample_event.json
└── _dev/
```

---

## ⚙️ 4. Configure Variables & Agent Template

### `data_stream/api/manifest.yml`

Define user inputs under `streams.vars`:

```yaml
streams:
  - input: cel
    title: My API
    description: Collect data from REST
    template_path: api.yml.hbs
    vars:
      - name: url
        type: text
        title: API Base URL
        required: true
      - name: token
        type: password
        title: Bearer Token
        required: true
      - name: interval
        type: text
        default: 5m
        title: Poll Interval
      - name: tags
        type: text
        multi: true
        default: ["forwarded", "my_api"]
      - name: preserve_original_event
        type: bool
        default: false
```

### `agent/stream/api.yml.hbs`

```hbs
config_version: 2
interval: {{interval}}
resource.url: {{url}}
auth.bearer: {{token}}

program: |
  // CEL expression fetching JSON, assigning to ctx.events

tags:
  {{#each tags as |t|}}
  - {{t}}
  {{/each}}

{{#if processors}}
processors:
{{processors}}
{{/if}}
```

---

## 🗂 5. Define Fields

Create:

* `base-fields.yml` — required ECS & datastream metadata.
* `beats.yml` — for `input.type`, `log.offset` (optional).
* `fields.yml` — ECS-aligned domain-specific fields.

Example `base-fields.yml`:

```yaml
- name: data_stream.type
  type: constant_keyword
  value: logs
- name: data_stream.dataset
  type: constant_keyword
  value: my_api.api
- name: '@timestamp'
  type: date
  description: Event timestamp
- name: event.module
  type: constant_keyword
  value: my_api
- name: event.dataset
  type: constant_keyword
  value: my_api.api
```

Example domain field in `fields.yml`:

```yaml
- name: my_api
  type: group
  fields:
    - name: id
      type: keyword
      description: Event ID
    - name: status
      type: keyword
    - name: timestamp
      type: date
    - name: message
      type: text
```

---

## 🧪 6. Ingest Pipeline

Path: `elasticsearch/ingest_pipeline/default.yml`

```yaml
processors:
  - set: { field: ecs.version, value: "8.13.0" }
  - set: { field: event.original, copy_from: _source }  # optional
  - json: { field: event.original, target_field: my_api.api }
  - dot_expander: { field: "*", path: my_api.api }
  - date:
      field: my_api.api.timestamp
      target_field: "@timestamp"
      formats: [ ISO8601 ]
  - set: { field: event.kind, value: event }
  - set: { field: event.id, copy_from: my_api.api.id }
  - rename:
      field: message
      target_field: my_api.api.message
      ignore_missing: true
on_failure:
  - append:
      field: error.message
      value: "{{{_ingest.on_failure_message}}}"
```

> 🔁 Add `script` processors for type coercion or cleanup logic.

---

## 🧪 7. Add Tests & Fixtures

Directory: `data_stream/api/_dev/test/pipeline/`

| File                         | Description                             |
| ---------------------------- | --------------------------------------- |
| `test-api.log`               | Raw input (from `task.md` cURL example) |
| `test-api.log-expected.json` | Expected doc after pipeline processing  |
| `test-api-config.yml`        | Optional: overrides for testing         |

Generate expected output:

```bash
elastic-package test pipeline --generate
```

Add one of the expected outputs as `sample_event.json` in `data_stream/api`.

---

## 📚 8. Add Build Metadata & Docs

### `_dev/build/build.yml`

```yaml
dependencies:
  ecs:
    reference: git@v8.13.0
    import_mappings: true
```

### `_dev/build/docs/README.md`

````markdown
# My API Integration

This integration collects events from a REST API.

## Data Streams

- **my_api.api** — Pulls logs from `{{url}}`

## Requirements

- Elasticsearch & Kibana ≥ 8.13.0
- API base URL and token

## Setup

1. Add the integration in Kibana.
2. Set API URL and token.
3. Configure polling interval and tags.

## Example Event

```json
{{{event "api"}}}
````

{{fields "api"}}

````

---

## 🧾 9. Finalize Manifests

### Root `manifest.yml`

```yaml
format_version: 3.0.0
name: my_api
title: My API
version: "0.1.0"
description: Ingest logs from My API via REST
type: integration
categories: [ custom ]
policy_templates:
  - name: my_api
    title: My API Logs
    inputs:
      - type: cel
        title: Pull logs from API
        description: Fetch data via API
owner:
  github: your-org
````

### `changelog.yml`

```yaml
- version: "0.1.0"
  changes:
    - description: Initial release.
      type: enhancement
```

---

## 🧪 10. Test and Iterate

Run:

```bash
elastic-package format
elastic-package lint
elastic-package build
elastic-package install
elastic-package test pipeline
elastic-package test static
elastic-package test asset
```

(Optional: if using a mock API)

```bash
elastic-package test system
```

> Iterate until all tests pass and install completes without warnings.

---

## 🚀 11. Future Enhancements

Not required for v0.1.0 but consider later:

* Dashboards
* System tests with mock API
* ML jobs
* Export visualizations:

  ```bash
  elastic-package export kibana
  ```

---

## 📝 Cheat Sheet

| Action               | Command                              |
| -------------------- | ------------------------------------ |
| Create package       | `elastic-package create package`     |
| Add data stream      | `elastic-package create data-stream` |
| Run all tests        | `elastic-package test`               |
| Format + lint        | `elastic-package check`              |
| Build + install      | `elastic-package build && install`   |
| Dev stack (optional) | `elastic-package stack up -d`        |
