# AGENTS Guide: Elastic Integrations Fork

This repository is a working fork of Elastic Integrations. It contains multiple integrations under `packages/` (for example `packages/ti_rapid7_threat_command` and `packages/rapid7_insightvm`). Day‑to‑day development and testing here centers around the `elastic-package` CLI and a local Elastic Stack running in Docker.

Keep this file practical and process‑oriented: how to run, test, lint, and document your work so the next agent can move fast.

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

## Issues
Only note problems you can’t fix or work around.
- Nothing listed yet.

---
