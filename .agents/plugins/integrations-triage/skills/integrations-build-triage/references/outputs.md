# Output templates

Rules shared by every public draft (summary, status, issue):

- Stands on its own: no references to local files, report section numbers or private log locations, and no UUIDs.
- Plain language first; technical detail only in the Evidence line. **Bold** anything that affects real users, not just tests.
- Full links. Buildkite evidence links to the log lines.
- Owner names the team (`@elastic/<team>` from CODEOWNERS / `owner.github`) **in backticks**. The user removes the backticks to ping.
- Counts add up to the issue's package list. Failed jobs outside the list get a one-line note.
- Never link the private report artifact from a public draft.

## Investigation report (private artifact)

Source is `build-<B>-report.md`, published as a Markdown artifact. Title: `Build <B> triage`. Icon: `chart`. Description: "Private triage report for build <B> (<stack>), elastic/integrations#<n>".

```markdown
# Build [<B>](…) triage report (stack <X>-SNAPSHOT)

| Field | Value |
|---|---|
| Build | link, pipeline name, date · commit · elastic-package version · jobs failed/passed/broken |
| Issue | #<n>: <K> packages listed, matches <K> failed jobs? |
| Control | same-night released-stack build and its result |

Confidence: ✅ confirmed · 🟡 inferred · 🔍 not investigated.

## Summary by cause
| # | Cause | Pkgs | Test | Confidence | Owner | Tracked |

## 1. <Cause> (<n> packages) ✅
| Package | Failing test | Evidence (log link) |
<cause, bisect (first failing build), upstream refs at pinned SHAs, private-log findings, repro steps + result>
> Revised <date>: <what a deep dive changed vs the earlier hypothesis>

## Delta vs prior hypotheses
## Issues to file  (group | package | repo | owner | labels | draft | status)
## Next steps
```

## TRACKING.md (local, the source of truth)

```markdown
# Tracking: elastic/integrations#<n>, <issue title>
- Report (private): <artifact URL>
- Stack: <X>-SNAPSHOT · Reference build: [<B>](…) (<date>) · First failed: <B0> · Updated: <date>

| # | Package | Cause (short) | Confidence | Owner | Issue | Status |
|---|---|---|---|---|---|---|
| 1 | <pkg> | … | ✅/🟡/🔍 | package owners `@elastic/<team>` | [#N](…) | ✅ tracked / 🔄 fix in progress / ⏳ to file / 🔍 to investigate / ✔️ fixed (dropped out on <date>) |

## Delta
<new / fixed vs previous night and vs the first build, from scope.sh>

## Next steps
- [ ] …
```

## Summary (comment on the auto-filed issue)

```markdown
# Nightly build [<B>](https://buildkite.com/elastic/integrations/builds/<B>): why <K> packages failed

[Build <B>](…) ran every package against the <X> snapshot stack. **The <K> packages listed in this issue failed from <C> different causes.** <Control: did they pass on the released stack?> <What's new since the last report.>

## At a glance

| Packages | What's wrong | Owner | Next step |
|---:|---|---|---|
| **5** | <plain-language problem> | package owners | 📌 Already tracked ([#N](…)) |
| 1 | <pkg>: … **affects real users** | `@elastic/<team>` | 🛠 Fix in this repo (package) |
| 1 | <pkg>: … | elastic-package | 📝 Issue to file in `elastic/elastic-package` |

**Legend:** 📝 issue to file in that repo · 🛠 fix in this repo · 📌 already tracked · 🔁 retry should pass · 🔍 not investigated yet

---

## Details

### 1. <Problem> (<n> packages)
- **Root cause:** <1–3 sentences; upstream PR and whether it's released>
- **Evidence:** <one line + [log](…#job/start-end)>
- **Next:** <repo/owner + urgency>
- **Packages:** a, b, c

> **Status <date>:** <added later by Mode C/D, under the item it concerns>
```

## Status comment (Mode D)

```markdown
## Status update (<date>): build [<B>](…), <K> packages

### ✅ Investigated, tracked, waiting on the owning team
| Packages | Cause | Tracked in | Status |

### 🔄 Fix in progress
| Packages | Cause | Fix (PR, release, where it must land) |

### ⏳ Cause known, nothing filed yet
| Packages | Cause | Next step |

### 🔍 Not investigated
- **<pkg>**: <symptom>
```

## Owner issue draft (`ISSUE_DRAFT_<topic>.md`)

```markdown
**Title:** [<pkg>] <symptom>: <when/where it fails>
**Labels:** Integration:<pkg>, Team:<team>, <bug|flaky-test>
---
## Summary
<2–3 sentences: what fails, since when (first failing build + date), on which stacks>
## Evidence
- <log line + Buildkite link>, <hit progression / timeline>, <passing vs failing build>
## Cause
<proof: code at a pinned SHA, repro steps. No private log content>
## Suggested fix
<only if verified locally; otherwise omit and leave it to owners>
## Related
<auto-filed "Failing test daily" issues this explains, sibling fixes, #<parent issue>>
```

Post-ready body: everything after `---`. The user runs `gh issue create --title … --body-file <(sed '1,/^---$/d' ISSUE_DRAFT_x.md)`.

## Superseded banner (top of every draft when scope.sh says SUPERSEDED)

```markdown
> [!IMPORTANT]
> **SUPERSEDED by #<successor> (<successor prefix>). This issue will not be updated again.** <Why: updatecli moved the job from <old> to <new> (#<pr>, <date>), and the reporter matches issues by exact title.> Build <B> (<date>) is final. **Proposal: close #<n>.**
```

## Close comment for a superseded issue (`COMMENT_DRAFT_close_superseded.md`)

Ecosystem closes "Too many" issues as **completed**, with a short comment that starts "Closing this issue since …" and links the evidence (e.g. #18575, #20949). Follow that style:

```markdown
Target: <issue URL>, then close (as completed)

---

Closing this issue, since it has been superseded since <date> and the daily job no longer writes to it.

- Its last failing build is [<B>](…) (<date from the edit log>). <updatecli moved the job from `<old>` to `<new>` (#<pr>) on <date>.>
- The reporter finds its issue by exact title, and the title includes the stack version, so every bump starts a new issue<; that happened for <range> (#a … #b, all closed)>. <If updatedAt is later: its last activity (<date>) was <the stale bot>, not the daily job.>
- <Successor: failures are now tracked in #<successor>.> OR <The job runs on `<new>` today. The latest run, [<lb>](…) (<date>), stayed under the 30-failure threshold, so its failures are tracked in the per-package `<prefix> [<package>] Failing test daily: …` issues.>
```
