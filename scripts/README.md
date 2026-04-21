# Scripts

This directory contains utility scripts for the `elastic/integrations` repository.

---

## `generate_obs_infraobs_report.py`

Generates a Markdown report listing every integration and data stream owned by the
GitHub team **`@elastic/obs-infraobs-integrations`**, together with the Elastic Agent
input type(s) each data stream uses.

### Prerequisites

- Python 3.8 or later
- [PyYAML](https://pyyaml.org/)

Install the dependency with:

```bash
pip install pyyaml
```

### Usage

Run from the repository root:

```bash
python3 scripts/generate_obs_infraobs_report.py
```

By default the report is written to:

```
docs/obs-infraobs-integrations-input-types.md
```

#### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--repo-root PATH` | parent of `scripts/` | Path to the root of the `elastic/integrations` clone |
| `--output PATH` | `docs/obs-infraobs-integrations-input-types.md` | Destination Markdown file |
| `--stdout` | off | Also print an ASCII table to standard output |

#### Examples

```bash
# Write report to the default location and show the table in the terminal
python3 scripts/generate_obs_infraobs_report.py --stdout

# Write to a custom path
python3 scripts/generate_obs_infraobs_report.py --output /tmp/report.md

# Run against a different clone
python3 scripts/generate_obs_infraobs_report.py --repo-root /path/to/integrations
```

### How it works

1. **Ownership detection** – Parses `.github/CODEOWNERS` to build:
   - A set of *packages* whose top-level `/packages/<pkg>` entry lists
     `@elastic/obs-infraobs-integrations` as an owner.
   - A map of per-data-stream ownership overrides
     (`/packages/<pkg>/data_stream/<ds>`), so that for mixed-ownership
     packages (such as `aws`) only the data streams explicitly assigned to
     the team are included.

2. **Input type extraction** – For each relevant data stream the script reads:
   - `packages/<pkg>/data_stream/<ds>/manifest.yml` → `streams[].input` field
     (primary, authoritative source).
   - `packages/<pkg>/data_stream/<ds>/agent/stream/*.yml.hbs` → used as file-path
     evidence when the hbs stem matches the manifest input name, or as a
     fallback when no manifest `streams` section is present.

3. **Output** – Produces a Markdown table with columns:
   `Package | Data Stream | Input Type | Evidence (file path)`.

### Refreshing the committed report

The generated file `docs/obs-infraobs-integrations-input-types.md` is checked in to
the repository.  Re-run the script and commit the updated file whenever:

- new integrations are added or removed from the team's ownership,
- a data stream changes its input type, or
- you want to verify the report is up to date.

```bash
python3 scripts/generate_obs_infraobs_report.py
git add docs/obs-infraobs-integrations-input-types.md
git commit -m "docs: refresh obs-infraobs input types report"
```
