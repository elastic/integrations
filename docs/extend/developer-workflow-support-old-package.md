---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/developer-workflow-support-old-package.html
---

# Release a bug fix for supporting older package version [developer-workflow-support-old-package]

When a bug fix needs to be released for an older package version, the backport workflow handles most of the process automatically: branch creation, cherry-picking, changelog syncing, and PR assignment. The steps below cover how to set up a backport branch and apply a fix. For example: in this [PR](https://github.com/elastic/integrations/pull/3688) (AWS package version 1.23.4), support for Kibana version 7.x was dropped and the AWS package version was bumped from 1.19.5 to 1.20.0. A bug was later found in the EC2 dashboard that needed to be fixed for Kibana version 7.x, so instead of adding a new AWS package version 1.23.5, a fix was needed between 1.19.5 and 1.20.0 — creating a new version (for example, 1.19.6) based on 1.19.5.

**Contents:**

- [Overview of the process](#overview-of-the-process)
  - [Step 1: Find the git commit for the target package version](#step-1-find-the-git-commit-for-the-target-package-version)
  - [Step 2: Add a backport branch entry and open a PR](#step-2-add-a-backport-branch-entry-and-open-a-pr)
  - [Step 3: Create a PR for the bug fix](#step-3-create-a-pr-for-the-bug-fix)
  - [Step 4: Update changelog in main](#step-4-update-changelog-in-main)
- [Package owner synchronization](#package-owner-synchronization)
- [Backport checklist comment](#backport-checklist-comment)
- [Known issues](#known-issues)

## Overview of the process

1. [Find the git commit for the target package version](#step-1-find-the-git-commit-for-the-target-package-version)
2. [Add a backport branch entry and open a PR](#step-2-add-a-backport-branch-entry-and-open-a-pr) *(skip if the branch already exists)*
3. [Create a PR for the bug fix](#step-3-create-a-pr-for-the-bug-fix)
4. [Update the changelog in main](#step-4-update-changelog-in-main)

> The [backport checklist comment](#backport-checklist-comment) on PRs targeting `main` drives step 3 automatically for most cases — tick the branches you want and the workflow creates the backport PRs on merge.

### Step 1: Find the git commit for the target package version

In the example above, the commit to be fixed is the one right before this [PR](https://github.com/elastic/integrations/pull/3688) updating package `aws`:

* Using the web:

    * Look for the merge commit of the PR

        * [https://github.com/elastic/integrations/commit/aa63e1f6a61d2a017e1f88af2735db129cc68e0c](https://github.com/elastic/integrations/commit/aa63e1f6a61d2a017e1f88af2735db129cc68e0c)
        * It can be found as one of the last messages in the PR ![merged commit](images/merge_commit_message.png "")
        * And then show the previous commits for that changeset inside the package folder (e.g. `packages/aws`):
        * [https://github.com/elastic/integrations/commits/aa63e1f6a61d2a017e1f88af2735db129cc68e0c/packages/aws/](https://github.com/elastic/integrations/commits/aa63e1f6a61d2a017e1f88af2735db129cc68e0c/packages/aws/) ![commits from package](images/browse_package_commits.png "")

* Using the command line:

    * Using the helper script `dev/scripts/get_release_commit.sh`, which finds the commit directly from the package name and version:

        Syntax:
        ```bash
        ./dev/scripts/get_release_commit.sh -p <package_name> -v <version>
        ```

        Example:
        ```bash
        $ ./dev/scripts/get_release_commit.sh -p aws -v 1.19.5
        8cb321075afb9b77ea965e1373a03a603d9c9796
        ```

    * Alternatively, using `git log`:

        Syntax:
        ```bash
        git log --grep "#<pr_id>" -- packages/<package_name>
        git log -n 1 <merge_commit>^ -- packages/<package_name>
        ```

        Example:
        ```bash
        $ git log --grep "#3688" -- packages/aws
        commit aa63e1f6a61d2a017e1f88af2735db129cc68e0c
        Author: Joe Reuter <xx@email.de>
        Date:   Mon Aug 8 17:14:55 2022 +0200

            Inline all aws dashboards (#3688)

            * inline all aws dashboards

            * format

            * apply the right format

            * inline again

            * format
        $ git log -n 1 aa63e1f6a61d2a017e1f88af2735db129cc68e0c^ -- packages/aws
        commit 8cb321075afb9b77ea965e1373a03a603d9c9796
        Author: Mario Castro <xx@gmail.com>
        Date:   Thu Aug 4 16:52:06 2022 +0200

            Move lightweight manifest to integration for EBS data stream (#3856)
        ```

### Step 2: Add a backport branch entry and open a PR

The backport branch is created automatically when a new entry is merged into `.backports.yml`.

- **Recommended: use the `backport add-entry` subcommand**

  This command resolves the base commit automatically (combining steps 1 and 2) and inserts the entry in the correct position in the file. Build the tool from the repository root first:

  ```bash
  # Requires Go 1.26+ (see cmd/backport/go.mod)
  go build -C cmd/backport -o "$PWD/build/backport" .
  ```

  Then run:

  ```bash
  ./build/backport add-entry <package_name> <base_version>
  ```

  Example:
  ```bash
  $ ./build/backport add-entry aws 1.19.5
  Added: branch=backport-aws-1.19 base_commit=8cb321075afb9b77ea965e1373a03a603d9c9796
  ```

- **Alternatively: add the entry manually**

  Open a PR adding the entry for the branch you need:

  ```yaml
  - package: <package_name>
    branch: backport-<package_name>-<major>.<minor>
    base_version: "<version>"
    base_commit: "<commit_from_step_1>"
    maintained_until: null
    archived: false
    remove_other_packages: true
  ```

  Example for the `aws` package at version `1.19.5`:

  ```yaml
  - package: aws
    branch: backport-aws-1.19
    base_version: "1.19.5"
    base_commit: "8cb321075afb9b77ea965e1373a03a603d9c9796"
    maintained_until: null
    archived: false
    remove_other_packages: true
  ```

  Fields:

  * **`package`** — required. Package name as defined in the `name` field of `manifest.yml`.
  * **`branch`** — required. Name of the backport branch to create, following the format `backport-<package_name>-<major>.<minor>`.
  * **`base_version`** — required. The package version to branch from (e.g. `1.19.5`, `1.0.0-beta1`).
  * **`base_commit`** — required. The commit SHA found in the previous step.
  * **`maintained_until`** — optional. `null` for a new active branch. Set to a `YYYY-MM-DD` date when the branch has a known end-of-life: the branch is automatically excluded from the checklist and branch creation once that date passes (strictly before today in UTC). Prefer this over `archived: true` when the end-of-life date is known in advance.
  * **`archived`** — required. `false` for a new active branch. Set to `true` to immediately exclude the branch from the checklist and branch creation, with no fixed end-of-life date. Archiving does **not** delete the branch — packages can still be published from it; archiving only removes it from automated tooling.
  * **`remove_other_packages`** — required. `true`: the target package is kept along with its `requires.*` dependencies and `.link` file source packages, transitively expanded; all others are removed from `packages/`. `false`: all packages are kept. Set to `true` for the standard case — it keeps the branch lean and avoids running tests for unrelated packages on every PR.

Once the PR is opened, CI automatically:

* Validates the new entry schema (`check-backports-inventory`)
* Runs a **dry run** of the branch creation, which verifies that the package is published, the commit exists, the commit publishes the expected version, and the branch does not already exist — without pushing anything

The PR requires review from the `elastic/ecosystem` team (they are the CODEOWNERS of `.backports.yml`). Once merged to `main`, the branch `backport-<package_name>-<major>.<minor>` is created and pushed automatically. A comment is posted on the merged PR confirming success or failure of the branch creation.

When `remove_other_packages: true` is set in `.backports.yml` (the standard case), the backport branch is created with the target package and its `requires.*` dependencies and `.link` source packages, transitively expanded — all unrelated packages are removed. This keeps the branch lean and avoids running tests for unrelated packages on every PR opened against it.

### Step 3: Create a PR for the bug fix

- **Automatic: via the backport checklist**

  If the fix was merged to `main` with checklist branches ticked, the `auto-backport.yml` workflow creates the backport PR automatically — see [Backport checklist comment](#backport-checklist-comment). If the workflow encounters a conflict or error it marks the branch with ⚠️ in the checklist; use `backport_apply.sh` below to resolve it manually.

- **Manual: use `backport_apply.sh`**

  For ad-hoc backports, retries, or fixes applied directly to a backport branch, `backport_apply.sh` handles the entire process: cherry-picking the commit, bumping the patch version, writing the changelog entry, syncing package owners, and opening a PR.

  ```bash
  # Basic usage
  dev/scripts/backport_apply.sh \
    --sha <merge_commit_sha> \
    --package <package_name> \
    --target <branch_or_version> \
    --open-pr

  # With assignee resolution (pass the original PR number on main)
  dev/scripts/backport_apply.sh \
    --sha <merge_commit_sha> \
    --package <package_name> \
    --target <branch_or_version> \
    --open-pr \
    --origin-pr-number <pr_number>
  ```

  Required arguments:

  | Argument | Description |
  |----------|-------------|
  | `--sha` | Merge commit SHA of the bug fix PR on `main` to cherry-pick (minimum 8 characters). |
  | `--package` | Package name as it appears in `manifest.yml`. |
  | `--target` | Version series (e.g. `6.14`) or full branch name (e.g. `backport-aws-6.14`); the branch name is derived automatically from the version series. |

  Common optional flags:

  | Flag | Description |
  |------|-------------|
  | `--open-pr` | Create a GitHub PR after pushing the working branch. |
  | `--dry-run` | Commit locally and skip push and PR creation; use to review the result before opening a PR. |
  | `--origin-pr-number` | Number of the source PR on `main`; used to auto-assign the backport PR to the original author or merger. Optional — omit if running outside a PR context. |

  What the script does, in order:

  1. Fetches the backport branch and creates a local working branch (`auto-backport/<pkg>-<version>-<sha8>`).
  2. Cherry-picks `<sha>`, auto-resolving version-only conflicts in `manifest.yml`; restores `changelog.yml` to HEAD (it is regenerated in the next step).
  3. Bumps the patch version in `manifest.yml` and inserts a new `changelog.yml` entry (with a placeholder link that is fixed after the PR is opened).
  4. Syncs package owners from `main` as a separate commit — see [Package owner synchronization](#package-owner-synchronization).
  5. With `--open-pr`:
     1. Pushes the working branch and opens a PR against the backport branch.
     2. Replaces the placeholder link in `changelog.yml` with the real backport PR URL and pushes a second `Fix changelog link to backport PR` commit.

  If the cherry-pick conflicts on files beyond a version-line difference in `manifest.yml`, the script reports the conflicting files and cleans up. In this case, apply the fix manually using the alternative path below.

- **Alternative: manual cherry-pick**

  Create a new branch in your own remote (do **not** use a name starting with `backport-`), apply the bug fix, bump the patch version in `manifest.yml`, and add a `changelog.yml` entry. Open a PR targeting the backport branch.

  Once this PR is merged, the new version of the package is published automatically. The changelog sync to `main` (step 4) fires automatically — no manual action needed.

  For subsequent fixes to the same version, no new branch is needed — open a new PR against the same backport branch.

### Step 4: Update changelog in main

This step is handled automatically. When a backport PR is merged, the `sync-backport-changelog.yml` workflow fires and opens a PR against `main` that adds the new changelog entry for the backport version. The sync PR is created with two labels:

- `backport:sync-changelog` — identifies it as an automated sync PR.
- `changelog-link-check:skip` — skips the changelog link validation (the entry's link points to the backport PR, not the sync PR itself).

The sync PR is also automatically assigned: the workflow uses the backport PR's author if they are not a bot and have write/maintain/admin access on the repository, otherwise the merger if they are not a bot and have write/maintain/admin access. If neither qualifies, no assignee is set.

After the workflow runs, a comment is posted on the merged backport PR linking to the sync PR or reporting a failure. No manual action is needed.

**Retrying a failed sync:** if the workflow posts a failure comment, it includes a `/sync-changelog` retry hint. Any repository member with write, maintain, or admin access can re-trigger the sync by commenting `/sync-changelog` on the original merged backport PR — no dummy commit required. The workflow will overwrite any stale working branch left by the previous attempt and open the sync PR. Commenting on an unmerged PR exits silently with no side effects.

## Package owner synchronization

Backport branches are created from historical commits, so their `manifest.yml` owner field and `.github/CODEOWNERS` entries may be stale from the start and can drift further as packages change hands on `main`. Because GitHub resolves PR reviewers from the CODEOWNERS on the PR's **base branch**, a stale backport branch notifies the wrong team.

Two mechanisms keep owners in sync.

### Automatic sync during apply

When `backport_apply.sh` (a wrapper around `backport apply`) creates a backport PR, it automatically syncs the package's owners from `main` as a separate commit on top of the cherry-pick:

- **What is synced:** the `owner.github` field in `manifest.yml`, the package's own `.github/CODEOWNERS` line, and any sub-path entries nested under the package (data streams, `kibana/` directory, and other subdirectory overrides).
- **Commit message:** `Sync <package> package owners from main`
- **No-op:** if the owners already match `main`, the commit is skipped silently.
- **Warn-and-continue:** if `main` cannot be fetched, a warning is printed and the apply continues without syncing. If the package no longer exists on `main`, the sync is skipped silently. The backport PR is still opened; the CI check below surfaces any remaining mismatch.

### CI check: `check-backport-owners`

A Buildkite step runs on every pull request targeting a `backport-*` branch (triggered when `packages/**` or `.github/CODEOWNERS` changes) and posts a comment on the PR with one of three outcomes:

- **✅ In sync** — `Package owners are in sync with main.` No action needed.
- **Mismatch** — `Package owners are out of sync with main:` followed by a list of packages and the team(s) they should now be owned by. Update `manifest.yml` (`owner.github`) and `.github/CODEOWNERS` for each listed package to match the teams shown.
- **Check failed** — `The backport owner check failed to run` with a link to the build log. This is usually a transient network error fetching `main`; re-run the build.

The step is currently `soft_fail: true` — a mismatch posts a warning comment but does not block merge.

## Backport checklist comment

This section describes the backport checklist that appears on eligible pull requests targeting `main` (those that touch at least one package with active backport branches) — not just hotfix flows. If you landed here looking for "what is this comment on my PR?", this is the right place.

When you open or update a pull request targeting `main`, the `post-backport-checklist.yml` workflow automatically posts a comment listing the active backport branches for every package touched by that PR. The comment is recreated (deleted and re-posted) on each push — any manual edits are overwritten, and the PR author receives a fresh notification. It only appears when at least one package in the PR's diff has active backport branches in `.backports.yml`.

Example comment:

```
## Backport branches

> [!IMPORTANT]
> Only branches for packages touched by this PR's current diff are shown.
> This comment is updated automatically on each push — manual edits will be overwritten.

Tick the branches you want to backport to. PRs will be created automatically on merge, or when you update this checklist after merge.

Backport a change when it fixes behavior a branch already has; leave new behavior on `main`. See [when and why to backport](https://github.com/elastic/integrations/wiki/Package-Backports) if you are unsure.

**aws**
- [ ] `backport-aws-1.19` (maintained until 2027-06-30)
- [ ] `backport-aws-6.x`

---

> [!TIP]
> If a branch above is no longer required, set `archived: true` in its entry in `.backports.yml` to stop it appearing here.
> If the branch has a known end-of-life date, prefer `maintained_until: "YYYY-MM-DD"` — it will be excluded automatically once that date passes (strictly before today in UTC).
```

Tick a checkbox for each branch you want to backport to. When the PR merges into `main`, the `auto-backport.yml` workflow reads the comment and automatically creates a backport PR for every checked branch, updating the comment in real time (✅ = success, ⚠️ = conflict or error). Each backport PR is automatically assigned to the original PR's author (if they are not a bot and have write/maintain/admin access on the repository) or to the merger (if they are not a bot and have write/maintain/admin access on the repository). Checking a previously-unchecked branch after the PR has already merged also triggers the workflow to create the missing backport PR. If you do not intend to backport, leave all checkboxes unticked.

**Suppressing a branch from the checklist:**

To stop a branch appearing in the checklist, update its entry in `.backports.yml`:

- **`archived: true`** — excludes the branch immediately, with no fixed end-of-life date.
- **`maintained_until: "YYYY-MM-DD"`** — excludes the branch automatically once that date passes (strictly before today in UTC); preferred when the end-of-life date is known.

Archiving a branch does not delete it. Packages can still be published from an archived branch; archiving only removes the branch from the checklist and branch creation.

**Suppressing a package from the checklist:**

To hide all checklist entries for a package across all PRs, add it to the top-level `skip_checklist_packages` list in `.backports.yml`:

```yaml
skip_checklist_packages:
  - security_detection_engine
```

Packages in `skip_checklist_packages` are excluded from the checklist comment (no checkboxes are shown) but still participate in changelog syncing and other automated backport flows. Use this for packages whose backport workflow is managed separately.

## Known issues

These issues occur when working on backport branches based on older commits where CI infrastructure has since changed. If CI on your backport branch is failing with an unfamiliar error, check here first.

1. Missing `elastic-package stack shellinit` in backport branch:

    * **Affected versions**: `elastic-package` < v0.86.0. From v0.86.0 onward, `elastic-package` reads the stack connection settings (Elasticsearch host, username, password, CA cert) automatically from the current profile, so `shellinit` is no longer required.

    * Example of the error:

        `Error: could not create kibana client: undefined environment variable: ELASTIC_PACKAGE_KIBANA_HOST. If you have started the Elastic stack using the elastic-package tool, please load stack environment variables using 'eval "$(elastic-package stack shellinit)"' or set their values manually`

    * **Solution**: add elastic-package stack shellinit command in `.buildkite/scripts/common.sh`.

        * `eval "$(elastic-package stack shellinit)"`

            Example: [https://github.com/elastic/integrations/blob/0226f93e0b1493d963a297e2072f79431f6cc443/.buildkite/scripts/common.sh#L828](https://github.com/elastic/integrations/blob/0226f93e0b1493d963a297e2072f79431f6cc443/.buildkite/scripts/common.sh#L828)

2. License file not found in backport branch:

    * Example of the error:

        `Error: checking package failed: building package failed: copying license text file: failure while looking for license "licenses/Elastic-2.0.txt" in repository: failed to find repository license: stat /opt/buildkite-agent/builds/bk-agent-prod-gcp-1703092724145948143/elastic/integrations/licenses/Elastic-2.0.txt: no such file or directory`

    * **Solution**: Remove line defining `ELASTIC_PACKAGE_REPOSITORY_LICENSE` environment variable.

        * Example: [https://github.com/elastic/integrations/blob/0daff27f0e0195a483771a50d60ab28ca2830f75/.buildkite/pipeline.yml#L17](https://github.com/elastic/integrations/blob/0daff27f0e0195a483771a50d60ab28ca2830f75/.buildkite/pipeline.yml#L17)

3. Unknown flag `--coverage-format` in backport branch:

    * Example of the error:

        `Error: unknown flag: --coverage-format`

    * **Cause**: The `--coverage-format` flag was introduced in `elastic-package` v0.96.0 (2024-01-18). Backport branches based on commits predating that release use an older `elastic-package` version that does not recognise the flag.

    * **Solution**: Remove the `--coverage-format` flag from the relevant script on the backport branch.

4. Docker Compose YAML unmarshal error in backport branch:

    * Example of the error:

        `Error: error running package system tests: could not complete test run: could not setup service: could not get Docker Compose configuration for service: yaml: unmarshal errors: line 8: cannot unmarshal !!seq into map[string]string`

    * **Affected versions**: `elastic-package` < v0.96.0.

    * **Cause**: `elastic-package` < v0.96.0 always calls the standalone `docker-compose` binary directly (not the `docker compose` CLI plugin). A CI infrastructure update replaced the standalone binary installation (`with_docker_compose`) with the Docker CLI plugin (`with_docker_compose_plugin`). Docker 26.1.2+ ships `docker-compose-plugin` v2.24.7+ as a system binary, which `elastic-package` < v0.96.0 picks up instead of the pinned version. Docker Compose v2.23+ changed the `environment` field in its config output from a YAML map to a sequence (`!!seq`), which the older `elastic-package` struct (`Environment map[string]string`) cannot unmarshal. Pinning `DOCKER_COMPOSE_VERSION` in the pipeline file does not help because that variable only controls the CLI plugin installed at `~/.docker/cli-plugins/`, which pre-v0.96.0 elastic-package never uses.

        From v0.96.0 onward, `elastic-package` tries `docker compose` (CLI plugin) first and falls back to `docker-compose` (standalone), so it picks up the pinned plugin version and the error does not occur.

    * **Solution**: On the backport branch, make the following changes (see [example commit](https://github.com/elastic/integrations/commit/fbf68eb4a3f5baa928d930ed2408982f8cb3c54b)):

        1. Revert `DOCKER_COMPOSE_VERSION` in `.buildkite/pipeline.yml`, `.buildkite/pipeline.publish.yml`, and `.buildkite/pipeline.serverless.yml` back to the value that was in use on that branch before the CI sync (e.g. `v2.17.2`). The variable controls which standalone binary is downloaded, so it must match a version < v2.23.0 to avoid the `!!seq` format.
        2. Restore the `with_docker_compose` function in `.buildkite/scripts/common.sh` (which downloads and installs the pinned standalone `docker-compose` binary into `${BIN_FOLDER}`, the first entry on `PATH`).
        3. Call `with_docker_compose` from `test_one_package.sh` and `test_integrations_with_serverless.sh` alongside any existing plugin installation.

        This ensures `elastic-package` < v0.96.0 finds the pinned standalone binary before the system-installed v2.24.7+.


