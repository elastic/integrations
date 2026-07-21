---
name: validate-integration-docs
description: Lint an Elastic integration package's markdown with vale and propose fixes. Use when the user says "vale check," "lint docs," "validate the README," "check integration markdown," or wants to polish an integration's docs before opening a PR. Filters out false positives inside Go-template comment blocks in _dev/build/docs/, then re-runs vale against the rendered docs/ output after `elastic-package build` as a final pass.
compatibility: Requires `elastic-package` CLI and `vale` on PATH. Designed for packages in elastic/integrations (or any repo using the _dev/build/docs/README.md → docs/README.md layout produced by elastic-package build).
license: Apache-2.0
metadata:
  origin: elastic/elastic-package
---

# validate-integration-docs

Lint an integration package's docs source, filter template noise, propose fixes, then verify the rendered output.

## Phase 1 — Lint the source

1. **Check prerequisites**: run both checks before continuing:
   - `vale --version` — if not found, tell the user to install it by following the [Elastic vale linter guide](https://www.elastic.co/docs/contribute-docs/vale-linter#use-the-vale-linter-locally).
   - `elastic-package version` — if not found, tell the user to install it by following the [elastic-package install guide](https://github.com/elastic/elastic-package#getting-started).

   Stop and report any missing tools before proceeding.

2. **Locate the package root**: find the nearest ancestor directory (including cwd) that contains both `manifest.yml` and `_dev/build/docs/README.md`. If not found, ask the user for the path before continuing.

3. **Run vale** on the source:

   ```bash
   vale _dev/build/docs/README.md --output JSON
   ```

   If additional `*.md` files exist under `_dev/build/docs/`, include them too.

4. **Detect template-comment ranges**: pre-scan the source file with a non-greedy DOTALL match for `\{\{\s*/\*.*?\*/\s*\}\}`. For each match, record `(start_line, end_line)` by counting newlines before the match start and end.

5. **Filter findings**: suppress any vale finding whose `Line` falls within any `(start_line, end_line)` range. Those lines are stripped by `elastic-package build` and their findings are false positives. Report only findings outside those ranges, grouped by file, with: Line, Match, Severity, Check, and Message.

6. **Draft proposals** for each reported finding:
   - `Action.Name == "replace"` → mechanical substitution using `Action.Params[0]`.
   - `Action.Name == "remove"` → delete the `Match` span.
   - No action params (for example `Elastic.Semicolons`, `Elastic.DontUse`, `Elastic.Ellipses`) → draft a prose rewrite of the sentence using context.

7. **Confirm before editing**: present all proposals together and ask the user which to apply (all / subset / none). Apply only confirmed edits via the Edit tool. **Never edit files under `packages/*/docs/`** — only `_dev/build/docs/` sources.

If Phase 1 finds no actionable issues, skip the confirmation step and proceed to Phase 2.

## Phase 2 — Build and re-lint the rendered output

1. **Build** the package from the package root:

   ```bash
   elastic-package build
   ```

2. **Run vale** on the rendered README:

   ```bash
   vale packages/<pkg>/docs/README.md --output JSON
   ```

   Extend to other `docs/**/*.md` if present. No template-comment filtering is needed — comments are stripped by the build.

3. **Report and propose fixes** exactly as in Phase 1 steps 6–7. If a Phase 2 finding maps to a source line, edit `_dev/build/docs/` only.

4. **Re-run** `elastic-package build` after any source edits so the user can confirm the rendered output is clean.

## Review checklist

Before reporting the task complete, verify:

- [ ] `vale` and `elastic-package` were both confirmed available (or the user was sent to the relevant install guide).
- [ ] Every finding inside a `{{/* */}}` block was suppressed in Phase 1.
- [ ] No edits were written to any path under `packages/*/docs/`.
- [ ] Every edit was confirmed by the user — nothing was silently auto-applied.
- [ ] `elastic-package build` completed without error.
- [ ] `vale packages/<pkg>/docs/README.md` (Phase 2) reported no findings.
