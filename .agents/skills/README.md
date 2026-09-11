# Agent skills

This directory bundles agent skills that help develop Elastic integrations.
Each skill lives in its own folder under `.agents/skills/` and ships with a
`SKILL.md` describing what it does and when it triggers.

## Install

Install every skill in this directory with [`npx skills`](https://www.npmjs.com/package/skills):

```bash
npx skills@latest add https://github.com/elastic/integrations/tree/main/.agents/skills
```

Running this opens a wizard that adds the skills to your preferred agents
(Claude Code, and any other agent the `skills` CLI supports). After installation
each skill auto-activates when its trigger conditions match — see the
individual `SKILL.md` for the exact phrases that invoke it.

## Installing from a branch

The URL accepts any `tree/<branch>/.agents/skills` reference, so you can install
skills from an unmerged branch — useful for reviewing or trying a skill
before it lands on `main`:

```bash
npx skills@latest add https://github.com/elastic/integrations/tree/<branch>/.agents/skills
```

Swap `<branch>` for the branch you want. Re-running `npx skills add`
with a different branch URL re-installs from that source, so you can move
between branches and `main` as needed.
