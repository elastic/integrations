# Sub-agent prompt: Domain knowledge

Use this prompt when dispatching a sub-agent to create the initial product domain document for an Elastic integration.

## Variables

| Variable | Description | Example |
| --- | --- | --- |
| `{integration}` | Package name under `packages/` | `wiz` |
| `{output_path}` | Path to the markdown file to create | `dev/domain/p1/wiz.md` |
| `{repo_root}` | Absolute path to the integrations repo | `/Users/.../integrations` |

## Scope guardrails

Each sub-agent analyzes **`{integration}` only**.

**Allowed reads:** `packages/{integration}/**`, web search for this vendor product when package docs are thin.

**Forbidden:** other `dev/domain/p1/*.md` files, other `packages/*/` directories, copying prose from another integration's domain doc.

## Package capability (mandatory check)

Read [package-capability.md](package-capability.md). Before writing **Data Collected**:

1. Check whether `packages/{integration}/data_stream/` exists and `manifest.yml` has `policy_templates`.
2. If **no** — this is **assets-only** (dashboards/content). Do not list Elastic Agent data streams.

## Prompt template

```
Create a markdown file describing the product domain for the Elastic integration "{integration}".

Steps:
1. Read packages/{integration}/ only — manifest.yml, docs/README.md, and any other relevant markdown at {repo_root}/packages/{integration}/. Do not read other integrations' domain docs or packages.
2. Optionally use web search to understand the vendor product domain if package docs are thin.
3. Write file: {repo_root}/{output_path}

Format:

# {integration}

## Product Domain

Write 2–4 paragraphs covering:
- What the vendor product is and its primary domain/category (e.g. CNAPP, NGFW, IAM, MDM)
- Key capabilities and typical deployment context
- How security / platform / IT teams use it
- How the Elastic integration fits (high level)

## Package capability

One line: **agent-backed** | **assets-only** | **assets-with-sibling** (see package-capability.md).

## Data Collected (brief)

**If agent-backed** (`policy_templates` + `data_stream/` present):
- List each data stream from manifest with a one-line description
- Note collection method (API, syslog, S3, Event Hub, etc.)

**If assets-only** (no `data_stream/`, no `policy_templates`):
- State explicitly: **This package provides Kibana assets only — no Elastic Agent data streams or ingest pipelines in-repo.**
- List bundled dashboards / saved searches and expected customer index patterns (e.g. `logs-corelight-*`, `data_stream.dataset` / `event.dataset` values from dashboard ES|QL if documented)
- Describe how data reaches Elasticsearch per package README (external export, OTel, etc.)
- Do **not** invent `data_stream.*` entries that are not defined in this package's manifest

Rules:
- Keep it factual and concise
- Ground descriptions in package docs; use web search only to fill gaps
- Do not invent data streams that are not in the package
- Return the file path when done
```

## Example invocation

Integration: `qualys_vmdr`  
Output: `dev/domain/p1/qualys_vmdr.md`

## Notes

- One sub-agent per integration keeps context focused and token use low.
- Sub-agents do not see the full conversation — include all paths, the integration name, and [Scope guardrails](#scope-guardrails) in the prompt.
- This pass creates the file from scratch; the actor/target pass appends to it later.
