# AGENTS Guide: Elastic Integrations Fork

This repository is a working fork of Elastic Integrations. It contains multiple integrations under `packages/` (for example `packages/ti_rapid7_threat_command` and `packages/rapid7_insightvm`). Day‑to‑day development and testing here centers around the `elastic-package` CLI and a local Elastic Stack running in Docker.

Keep this file practical and process‑oriented: how to run, test, lint, and document your work so the next agent can move fast. SUPER IMPORTANT: UPDATE THIS FILE when you encounter friction using the tools or workflows described here and dont expect this file to be perfect or complete. It’s a living document. DEFINETLY ADJUST IT to your needs.

## Golden Rules
- Prefer `elastic-package` for local dev, testing, formatting, linting, building, and installing packages.
- Always verify the local stack is running before testing.
- Keep changes documented: short notes in `docs-logs/`, deeper writeups in `docs-dev/`.
- Don’t commit secrets. Don’t fight the spec: follow the package spec in `docs/extend/`.

## Repo Structure (essentials)
- `packages/` — integration packages. Each has a `manifest.yml`, optional `kibana/`, one or more `data_stream/` subfolders, `_dev/test/…` fixtures, etc.
- `docs/extend/` — upstream guidance and spec. Start here to understand allowed assets and structure (see `docs/extend/package-spec.md:6`).
- `docs-logs/` — change logs and how‑to notes. May be outdated by design; still valuable references.
- `docs-dev/` — local architecture/design notes you write for new features or deeper explanations.

## Tools You Can Use
- `elastic-package` — main CLI for stack, tests, lint/format, build, install.
- `docker` — used under the hood by `elastic-package stack` and for quick health checks.
- `rg` (ripgrep) — fast code search in this repo.

Installed here:
- `elastic-package v0.111.0` (verified) and `Docker 28.x` are available in PATH.

Tip: `elastic-package` will often suggest a newer version at runtime. Prefer the latest when you hit quirks (especially for system tests).

## Local Stack (READ THIS FIRST)

🚨🚨 IMPORTANT: Before running any tests, check if the Elastic stack is up.

- Check status:
  - Quick check: `docker ps | grep -E "(elastic|kibana|fleet|package-registry|agent)"`  
  - Or: `elastic-package stack status`
- If containers aren’t running, start the stack:
  - `elastic-package stack up -d`  
    - Brings up Elasticsearch, Kibana, Package Registry, Fleet Server, and Agent.
- When done for the day, you can stop it:
  - `elastic-package stack down`

Tips:
- Use `elastic-package stack status` anytime to confirm readiness (Kibana + ES green).  
- You can set a version with `STACK_VERSION=8.x.y elastic-package stack up -d` (see `docs/ci_pipelines.md:75`).
- If the stack fails to dump logs at the end of tests with messages about missing `elastic-agent` logs, ensure the stack includes the `elastic-agent` service and is healthy:
  - `elastic-package stack up -d -s elasticsearch,kibana,fleet-server,package-registry,elastic-agent`
  - Then re-run system tests.

Refreshing stack images:
- A simple `stack up` may reuse cached images. To force pulling new images, you can:
  - Change `--version` (e.g., `elastic-package stack up -d --version 8.17.4`), or
  - Stop the stack (`elastic-package stack down`) and then start again. If issues persist, consider `docker compose pull` inside the stack profile folder (advanced; see elastic-package profiles docs).

## Common Workflows

### 1) Format, Lint, Build
Run at repo root or inside a specific package directory.

```sh
# ensure stack is up first if you plan to test after
elastic-package format
elastic-package lint
elastic-package build
```

- `format` auto-formats package files.
- `lint` enforces package spec and content rules.
- `build` produces the package artifact (zip) in `build/`.

### 2) Install a Package into Kibana
From inside a package folder (e.g., `packages/ti_rapid7_threat_command`):

```sh
elastic-package install
```

- Installs the built package into the local Kibana from the running stack.

### 3) Run Tests
You can run tests at repo root (all packages) or inside a specific package.

- Everything:
```sh
elastic-package test
```

- Only certain test types:
```sh
elastic-package test pipeline  # ingest pipeline tests
elastic-package test static    # static checks (schemas, fields)
elastic-package test asset     # Kibana/ES assets
elastic-package test system    # end-to-end system tests
```

- Focus on a single data stream (from package root):
```sh
# example: threat command alert stream
cd packages/ti_rapid7_threat_command
echo "Run only the alert data stream" && \
  elastic-package test pipeline -d data_stream/alert
```

- Generate expected docs for pipeline tests (then refine):
```sh
elastic-package test pipeline --generate
# add or adjust sample_event.json and test cases under _dev/test/pipeline/
```

- Useful combined check before PRs:
```sh
elastic-package format && elastic-package lint && elastic-package test
```

Notes:
- System tests often require the stack and may require credentials or service mocks depending on the package. Start with `pipeline` and `static` for fast feedback.
- See upstream concepts and guardrails in `docs/extend/` (e.g., `docs/extend/general-guidelines.md:16`).

Test types quick guide:
- `pipeline`: runs ingest pipeline(s) locally against sample events. Fastest feedback; no mock containers.
- `static`: validates fields/schemas and `sample_event.json` per spec.
- `asset`: verifies assets (index template, pipeline) are loadable.
- `system`: end-to-end with Dockerized mock services and Elastic stack; asserts behavior in Elasticsearch (e.g., hit counts, indexed docs). Slower but realistic.

System tests lifecycle:
- Provision: builds package, installs it into Kibana, spins up an independent Elastic Agent plus your mock service (from `_dev/deploy/docker`).
- Exercise: Agent collects from the mock, data flows through ingest pipeline.
- Assert: Test harness checks expectations (e.g., `hit_count`).
- Teardown: Stops agent/service and attempts to dump stack logs for debugging.

### 4) Example: CrowdStrike Integration
Quick way to validate changes using the CrowdStrike package present in this fork.

```sh
# Check stack
elastic-package stack status || elastic-package stack up -d

# Format/lint/build repo-wide first (optional but recommended)
elastic-package format && elastic-package lint && elastic-package build

# Test a specific data stream
cd packages/crowdstrike
elastic-package test pipeline -d data_stream/vulnerability
elastic-package test static

# Install locally into Kibana (for manual UI checks if needed)
elastic-package install
```

## Where to Read First (Upstream Docs in this Repo)
- Pipeline, mapping, spec references: `docs/extend/package-spec.md:6`
- General authoring guidance: `docs/extend/general-guidelines.md:21`
- CI and environment variables for `elastic-package`: `docs/ci_pipelines.md:54`, `docs/ci_pipelines.md:75`

These upstream docs are the canonical source of truth for asset layout, data stream rules, and constraints.

## Documentation Workflow (Keep Things Organized)
- Top‑level `README.md` stays user‑facing. Keep it generic.
- `AGENTS.md` (this file) is for processes: tools, tests, and workflows.
- `docs-logs/`: add a new markdown file per feature/fix with what/why/how and file references. These can become outdated over time — that’s OK; they serve as historical notes and implementation breadcrumbs.
- `docs-dev/`: put deep dives, architecture notes, and design writeups here. Link them from `docs-logs/` entries when relevant.

When you change behavior or add features, create a `docs-logs/` entry and add deeper explanations in `docs-dev/` if needed.

## Style and Hygiene
- Follow the package spec rules; rely on `elastic-package lint` to catch issues.
- Keep test fixtures tidy under `data_stream/*/_dev/test/`.
- Prefer small, focused changes with clear `docs-logs/` notes.

## Troubleshooting
- Stack isn’t up: run `docker ps` and `elastic-package stack status`; if down, `elastic-package stack up -d`.
- Lint/format issues: run `elastic-package format` first, then re-run `elastic-package lint`.
- Tests failing locally but not obviously: re-run a single type (`pipeline`, then `static`) to bisect.
- Kibana/ES version mismatches: pin `STACK_VERSION` when bringing up the stack.
- System tests: common issues and fixes
  - Error copying elastic-agent logs (post-run dump): ensure `elastic-agent` service is running in the stack. Use `elastic-package stack up -d -s elasticsearch,kibana,fleet-server,package-registry,elastic-agent`.
  - Mock server templating errors (e.g., `function "Hostname" not defined`): avoid using `{{Hostname}}`/`{{Port}}` inside mock response bodies unless supported. Prefer static service URLs that match the mock container’s hostname and port (e.g., `http://bitsight-vulnerability:8090/...`).
  - Pagination verification: ensure mock config provides `links.next` and a second page route, then set `hit_count` > 1 in the system test config.
  - Inspect logs written to `build/container-logs/*` after system tests to diagnose mock/agent issues.

Recommended workflow sequence:
- `elastic-package format && elastic-package lint`
- `elastic-package test pipeline -d <stream>` and `elastic-package test static`
- `elastic-package test asset`
- `elastic-package test system -d <stream>` (only after stack is green and mock config verified)

Handy flags:
- `-d <data_stream>` to scope tests to a single data stream.
- `--generate` for pipeline tests to create expected outputs scaffold.

## Pull Request Reviews via `gh` (GitHub CLI)

Use this to extract reviewer tasks and maintain a single, readable log per PR. Write logs under `docs-logs/` for traceability, with correct heading hierarchy.

1) Fetch review comments for a PR URL

```sh
# Replace with your PR URL
PR=https://github.com/elastic/integrations/pull/14161

# Quick human view
gh pr view "$PR" --comments

# Machine-readable (JSON)
gh pr view "$PR" --json files,reviews,comments,title,author,url > /tmp/pr.json

# All review comments (line-anchored code review entries)
OWNER=elastic REPO=integrations NUM=14161
gh api repos/$OWNER/$REPO/pulls/$NUM/comments --paginate > /tmp/review_comments.json
```

2) Generate a markdown skeleton grouped by file (H1 title → H2 reviewer → H3 file)

```sh
OUT="docs-logs/$(date +%F) pr-$(basename $PR)-review.md"
echo "# Review Log for $PR" > "$OUT"
echo "Date: $(date -Iseconds)" >> "$OUT"
echo >> "$OUT"
echo "## Reviewer: efd6" >> "$OUT"

# Group comments by file with H3 per file, then bullets per line comment
jq -r '
  map(select(.user.login=="efd6"))
  | group_by(.path)[]
  | ("### " + .[0].path),
    (map("- L" + ( .line|tostring ) + ": " + (.body|gsub("\n";" ")) ) | .[])
' /tmp/review_comments.json >> "$OUT"
```

3) Write fixes and explanations directly under each reviewer item (no duplicates)
- For every bullet under a given `### <path>` section, append a block immediately below it:
  - Fix: concise summary of the applied change
  - Files: precise file references (path:line)
  - Explanation: 1–10 sentences (short for trivial, longer for nuanced changes)
  - Status: done/pending

4) Work item by item
- Apply patches (change code/tests/docs).
- Re-run format/lint/tests.
- Update the corresponding reviewer bullet in the same `docs-logs/...pr-...-review.md` file with:
  - Fix applied (what and where)
  - Why (intent, tradeoffs, links to similar example if applicable)
  - Test results snapshot

Tips
- Use `gh api ... | jq` to extract exact file+line references and comment bodies.
- When reviewers suggest code snippets, adapt them literally unless conflicting with spec or recent best practice.
- Keep the `docs-logs/...pr-...-review.md` tidy and up to date — it becomes your response plan when you reply on the PR.

## Issues
Only note problems you can’t fix or work around.
- Nothing listed yet.

---
