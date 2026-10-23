# Evaluations

`evals.json` holds the scenarios the skill must handle, in the format of Anthropic's
skill authoring guide: a query, the files it needs, and the behaviours a correct
answer shows.

## Running them

There is no built-in runner. For each scenario:

1. Start a fresh Claude Code session at the root of the integrations repo, with this
   skill installed: `npx skills@latest add
   https://github.com/elastic/integrations/tree/<branch>/.agents/skills` (see
   `.agents/skills/README.md`), or, while developing it, a symlink from
   `.claude/skills/columnar-readiness` to `.agents/skills/columnar-readiness` (git
   ignores `.claude/skills/`).
2. Ask the `query` verbatim.
3. Check the answer against every `expected_behavior` item. An item is met only if the
   answer states it; a report that implies it does not count.

Run them on every model the skill is used with (Haiku, Sonnet, Opus), and after every
change to `SKILL.md`, the references or `scripts/audit.py`.

## Keeping them current

The expected behaviours reflect the catalog as of 2026-09-28. When a package changes
(o365 fixes its nested mapping, a detection rule stops reading `_source`), update the
scenario rather than the skill. `python3 <skill-dir>/scripts/audit.py packages/<pkg>`,
run from the repo root, shows the current state of each package.
