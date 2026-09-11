# CI integrations pipelines

This section describes the CI pipelines available in this repository.

Currently, there are six different pipelines:
- https://buildkite.com/elastic/integrations: pipeline in charge of testing all packages using a local Elastic stack. More info at [section](#pull-requests-and-pushes-to-specific-branches).
- https://buildkite.com/elastic/integrations-serverless: pipeline in charge of testing all packages using an Elastic Serverless project. More info at [section](#serverless-pipeline).
- https://buildkite.com/elastic/integrations-publish: pipeline to publish the new versions of packages. More info at [section](#publish-packages).
- https://buildkite.com/elastic/integrations-schedule-daily/: pipeline running every night to test packages in different scenarios. More info at [section](#daily-job).
- https://buildkite.com/elastic/integrations-schedule-weekly/: pipeline running once per week to test packages in different scenarios. More info at [section](#weekly-job).
- https://buildkite.com/elastic/integrations-backport/: pipeline to create backport branches. Triggered automatically when a new entry is merged into `.backports.yml`, or manually from the UI by members of the `ecosystem` team. More info at [section](#backport-branches-pipeline).

## Pull Requests and pushes to specific branches

In every push to a Pull Request as well as commits to `main`, `backport-*`, or `feature/*` branches, this pipeline is triggered automatically: https://buildkite.com/elastic/integrations

This pipeline is in charge of testing the packages with a local Elastic stack.

Special comments that can be added in the Pull Request (by Elastic employees):
- `/test` or `buildkite test this`: a new build is triggered.
- `/test benchmark fullreport`: a new build is triggered creating a full benchmark report (it will be posted as a GitHub comment in the PR).
- `/test stack <version>`: a new build is triggered in [integration-test-stack pipeline](https://buildkite.com/elastic/integrations-test-stack) where
  the packages updated in the PR will be tested using the Elastic stack version `<version>` set in the comment.
    - The new build will appear as another check status (not required).
    - Examples:
        - `/test stack 8.17.0`
        - `/test stack 8.18.0-SNAPSHOT`
        - `/test stack 9.0.0-SNAPSHOT`

There are some environment variables that can be added into this pipeline to enable customizations:
- **FORCE_CHECK_ALL**: If `true`, this forces the CI to check all packages even if those packages have no file updated/added/deleted. Default: `false`.
- **STACK_VERSION**: Force the CI steps to spin up a specific Elastic stack version to run the tests. Default: unset.
    - If this variable is set, the packages tested are the ones that support that version according to the constraint set in their manifest (`conditions.kibana.version`).
    - Examples:
      | STACK_VERSION | Kibana constraint | Stack version used for testing |
      | :---: | --- | :---: |
      | `7.17.28` | `^7.17.0 \|\| ^8.15.0 \|\| ^9.0.0` | `^7.17.28` |
      | `7.17.28` | `^^8.15.0 \|\| ^9.0.0` | Skip |
      | `8.17.0-SNAPSHOT` | `^8.18.0 \|\| ^9.0.0` | Skip |
      | `8.19.0-SNAPSHOT` | `^8.15.0 \|\| ^9.0.0` | `^8.19.0-SNAPSHOT` |
      | `9.1.0-SNAPSHOT` | `^8.15.0 \|\| ^9.0.0` | `^9.1.0-SNAPSHOT` |
- **STACK_LOGSDB_ENABLED**: Enable LogsDB setting in Elasticsearch service. Default: `false`.
    - If this variable is set and `STACK_VERSION` is unset, the CI will ensure that the stack version running will be either the version used in PR builds or 8.17.0 (the GA version for LogsDB index mode), whichever is higher.
    - Examples:
      | Kibana constraint | Stack version used for testing |
      | --- | :---: |
      | `^8.15.0 \|\| ^9.0.0` | `^8.17.0` |
      | `^8.18.0 \|\| ^9.0.0` | `^8.18.0` |
      | `^7.18.0` | Skip |
- **ELASTIC_SUBSCRIPTION**: Set the subscription to be used in the Elastic stack (`basic` or `trial`). Default: `trial`.
- **PUBLISH_COVERAGE_REPORTS**: If `true`, it enables reporting coverage reports.
  Currently, it is just set for the build triggered with the current major Elastic stack from the daily job. Default: `false`.

Apart from these environment variables, [these other environment variables](https://github.com/elastic/elastic-package/blob/main/README.md#useful-environment-variables) related to `elastic-package` can be set too for further customizations.

These environment variables can be defined in different locations:
- In the [global `env` section](https://github.com/elastic/integrations/blob/5276ef63712f8f2311818770881688870e8422fe/.buildkite/pipeline.yml#L2).
- In the case of the scheduled daily job in each step. Some examples:
    - [Running tests with 7.x major Elastic stack](https://github.com/elastic/integrations/blob/5276ef63712f8f2311818770881688870e8422fe/.buildkite/pipeline.schedule-daily.yml#L21).
    - [Running tests with 8.x major Elastic stack](https://github.com/elastic/integrations/blob/d6d99792b90838d18844f6df9343bc5f16130666/.buildkite/pipeline.schedule-daily.yml#L32).

More details about this CI pipeline:

- Builds running in a Pull Request are canceled if a new commit is pushed to the PR branch.
- Builds running from `main`, `backport-*`, or `feature/*` branches are finished even if new commits are merged.
- As part of the Pull Requests, there are some benchmark files created and this data is pushed to the PR as a comment.
- This CI pipeline tries to test the minimum packages possible::
    - In the Pull Request context, it is checked the files modified/added/deleted in the given PR:
        - Those packages with changes (`packages/*`) will be added to the list of packages to be tested.
        - If files outside `packages` folder are updated (for example `go.mod` , `.buildkite/*`), all packages are going to be tested. There are some exceptions to this, for instance the `.github/CODEOWNERS` file or `.docs/` folder ([files excluded](https://github.com/elastic/integrations/blob/376fc891a1e6c662b4ef1897b118044faf51e7bf/.buildkite/scripts/common.sh#L695)).
    - In branches context (`main`, `backport-*`, or `feature/*`):
        - The latest Buildkite build that finished successfully in that branch is retrieved, and all the file changes in the working copy between the changeset of that build and the merged commit are obtained.
        - Given all those changes, the packages selected to be tested follow the same rules as in the PR.
        - **First push (no previous successful build):**
            - For `backport-*` and `feature/*` branches: the merge-base between the pushed commit and `origin/main` is computed to find commits exclusive to the branch. If those commits contain changes under `packages/`, the affected packages are tested. If only CI infrastructure files changed (for example `.buildkite/`, `dev/`), no package tests are run.
            - For `main`: diffs against `origin/main^` (the previous commit on main).
- Container logs, as they could contain sensitive information, are uploaded to a private Google Bucket.
- Packages are tested running the Elastic stack with the minimum Kibana version supported according to their manifest (`.conditions.kibana.version`). If a package defines a Kibana version that is not released yet, `elastic-package` will be using the SNAPSHOT version. This can be overridden if the STACK_VERSION variable is defined in the environment.
  In the following table, there are some examples:
    
  | STACK_VERSION env | Kibana Condition Package | Released | Elastic stack run |
  | :---:    | :---:                  | :---: | :---:             |
  | ""       | `^7.16.0 \|\| ^8.0.0`  | Yes   | `7.16.0`          |
  | ""       | `^8.12.0`              | Yes   | `8.12.0`          |
  | ""       | `^8.14.1`              | Yes   | `8.14.1`          |
  | ""       | `^8.15.0`              | No    | `8.15.0-SNAPSHOT` |
  | `8.14.0` | `^8.13.0`              | Yes   | `8.14.0`          |

  If the STACK_VERSION environment variable is defined, just the packages supporting that stack version are tested. For instance:

  | STACK_VERSION env | Kibana Condition Package | Tested |
  | :---:  | :---: | :---: | 
  | `7.17.0` | `^7.16.0 \|\| ^8.0.0` | Yes |
  | `7.17.0` | `^8.12.0`             | No  |
  | `8.12.0` | `^8.13.0`             | No  |
  | `8.14.0` | `^8.13.0`             | Yes |


## Publish packages

**Note**: Available only to Elastic employees.

For every Pull Request merged onto the `main` branch or any `backport-*` branches,
this pipeline is triggered automatically https://buildkite.com/elastic/integrations-publish to publish new versions
of the packages if any. These new versions are published and made available in https://epr.elastic.co.

Environment variables that can be defined in this pipeline:
- **DRY_RUN**: If `true`, packages will not be published. Default: `false`.
- **SKIP_PUBLISHING**: If `true`, not run at all publish procedures. Default: `false`.

These environment variables can be defined:
- At the [global `env` section](https://github.com/elastic/integrations/blob/d6d99792b90838d18844f6df9343bc5f16130666/.buildkite/pipeline.publish.yml#L3).
- At the [specific buildkite publish step](https://github.com/elastic/integrations/blob/d6d99792b90838d18844f6df9343bc5f16130666/.buildkite/pipeline.publish.yml#L37).
- In case of the [step from schedule-daily job](https://github.com/elastic/integrations/blob/d6d99792b90838d18844f6df9343bc5f16130666/.buildkite/pipeline.schedule-daily.yml#L61)
  (it needs to be added the `env` dictionary).

## Serverless Pipeline

**Note**: Available only to Elastic employees.

Pipeline in charge of testing all packages with an Elastic Serverless project (https://buildkite.com/elastic/integrations-serverless). 

This pipeline follows these steps:
1. Create an Elastic Serverless project of a given type. Currently supported: Observability or Security
1. For each package in the repository:
    1. Check if the package is supported in the given Elastic Serverless project.
        1. Packages can define which capabilities they need. Depending on those, the package could be available or not in the Serverless project, and therefore they will be tested or not.
            - [Capabilities defined for Observability projects](https://github.com/elastic/kibana/blob/40a2bdf651b0eabe5977367ad1b875e7581f0e31/config/serverless.oblt.yml#L145).
            - [Capabilities defined for Security capabilities](https://github.com/elastic/kibana/blob/40a2bdf651b0eabe5977367ad1b875e7581f0e31/config/serverless.security.yml#L77).
        1. There are some packages that are excluded in the Kibana configuration explicitly:
            - [Packages excluded in Observability](https://github.com/elastic/kibana/blob/7c5cf9c76e35925cba7e3bd57cc01d1fffae81a4/config/serverless.oblt.yml#L150).
            - [Packages excluded in Security](https://github.com/elastic/kibana/blob/7c5cf9c76e35925cba7e3bd57cc01d1fffae81a4/config/serverless.security.yml#L82).
    1. Runs test for all the selected packages:
        - Currently, [system tests are not run in Serverless](https://github.com/elastic/integrations/blob/5714f5665bbe3bc29b9e2444c6a94dbc2d5eebe9/.buildkite/scripts/common.sh#L803).
        - As in the pipeline for Pull Requests, container logs as they could contain sensitive information, they are uploaded to a private Google Bucket.
1. Deletes the Elastic Serverless project.

Environment variables that can be defined in this pipeline:
- **SERVERLESS_PROJECT**: Serverless project to be created to test packages. Default: observability.

This environment variable can be defined at:
- At the [global `env` section](https://github.com/elastic/integrations/blob/d6d99792b90838d18844f6df9343bc5f16130666/.buildkite/pipeline.serverless.yml#L3).
- In case of the schedule-daily job:
    - [trigger observability tests step](https://github.com/elastic/integrations/blob/d6d99792b90838d18844f6df9343bc5f16130666/.buildkite/pipeline.schedule-daily.yml#L46).
    - [trigger security test step](https://github.com/elastic/integrations/blob/d6d99792b90838d18844f6df9343bc5f16130666/.buildkite/pipeline.schedule-daily.yml#L56).


## Daily job

**Note**: Available only to Elastic employees.

Every night it is configured to run a daily job that will be in charge of testing all packages with different scenarios: https://buildkite.com/elastic/integrations-schedule-daily/

The schedules of this job can be checked [here](https://github.com/elastic/integrations/blob/27d5cd9bb5eee76ce4229312271ceddaba7ebc2c/catalog-info.yaml#L178-L204).

In these daily jobs, the environment variable `FORCE_CHECK_ALL` is set to `true` ensuring that all packages that fulfill all the requirements set in the pipeline are tested. Those other requirements are related to setting `STACK_VERSION`, `STACK_LOGSDB_ENABLED`, etc... or other environment variables. More details about these environments variables [here](#pull-requests-and-pushes-to-specific-branches).

The scenarios that are tested in this daily job testing all the affected packages are:

- Local Elastic stack running the latest 7.x version of the stack:
    - Environment variables:
        - `STACK_VERSION=7.17.X-SNAPSHOT`
    - Triggered pipeline: https://buildkite.com/elastic/integrations
- Local Elastic stack running the latest 8.x version of the stack:
    - Environment variables:
        - `STACK_VERSION=8.X.Y-SNAPSHOT`
    - Triggered pipeline: https://buildkite.com/elastic/integrations
- Local Elastic stack running the latest 8.x version of the stack with LogsDB setting enabled:
    - Environment variables:
        - `STACK_VERSION=8.X.Y-SNAPSHOT`
        - `STACK_LOGSDB_ENABLED=true`
    - Triggered pipeline: https://buildkite.com/elastic/integrations
- Local Elastic stack running the latest major version of the stack:
    - Environment variables:
        - `STACK_VERSION=9.X.Y-SNAPSHOT`
    - Triggered pipeline: https://buildkite.com/elastic/integrations
- Local Elastic stack running the same stack version defined in the package manifest with "basic" subscription:
    - Environment variables:
        - `ELASTIC_SUBSCRIPTION=basic`
    - Triggered pipeline: https://buildkite.com/elastic/integrations
- Local Elastic stack running either the version used in PR builds or 8.17.0 (the GA version for LogsDB index mode), whichever is higher, with "basic" subscription and LogsDB index mode enabled.
    - Environment variables:
        - `ELASTIC_SUBSCRIPTION=basic`
        - `STACK_LOGSDB_ENABLED=true`
    - Triggered pipeline: https://buildkite.com/elastic/integrations
- Elastic Serverless Observability project.
    - Triggered pipeline: https://buildkite.com/elastic/integration-serverless
- Elastic Serverless Security project.
    - Triggered pipeline: https://buildkite.com/elastic/integration-serverless

Those tests that have failed in these scenarios will be reported as GitHub issues notifying the owner teams as defined in `.github/CODEOWNERS` file.

As part of this pipeline, it is also ensured that the latest versions of the packages merged into `main` branch
have been published by triggering the pipeline https://buildkite.com/elastic/integrations-publish.

Each step triggering a new pipeline can be customized through environment variables. Environment variables that can
be used in each pipeline are detailed in the corresponding sections of each pipeline.

## Weekly job

**Note**: Available only to Elastic employees.

Every week it is configured to run a job that will be in charge of testing all packages with non-Wolfi Elastic Agent docker images: https://buildkite.com/elastic/integrations-schedule-weekly/

The schedule of this job can be checked [here](https://github.com/elastic/integrations/blob/2e72e8524728daca2d47c814d8042031b8f5804f/catalog-info.yaml#L145).

The scenarios that are tested in this weekly job are:

- Test packages with a local Elastic stack running the latest 8.x version of the stack with Elastic Agent images based on Ubuntu images:
    - Environment variables:
        - `STACK_VERSION=8.X.Y-SNAPSHOT`
    - Triggered pipeline: https://buildkite.com/elastic/integrations
- Test packages with a local Elastic stack running the latest major version of the stack with Elastic Agent images based on non-Wolfi images:
    - Environment variables:
        - `STACK_VERSION=9.X.Y-SNAPSHOT`
    - Triggered pipeline: https://buildkite.com/elastic/integrations

Each step triggering a new pipeline can be customized through environment variables. Environment variables that can
be used in each pipeline are detailed in the corresponding sections of each pipeline.

## Backport branches pipeline

**Note**: Available only to Elastic employees.

Releasing hotfixes from earlier versions of packages requires creating `backport-*` branches from specific commits in the `main` branch.
The pipeline https://buildkite.com/elastic/integrations-backport/ handles this creation and can be triggered in two ways:

- **Automatically (recommended)**: when a PR adding a new entry to `.backports.yml` is merged into `main`, the `integrations` pipeline detects the change and triggers the backport pipeline automatically. A comment is posted on the merged PR reporting success or failure of the branch creation.
- **Manually from the UI**: restricted to members of the `ecosystem` Buildkite team.

As part of the PR that modifies `.backports.yml`, CI automatically:
- Validates the new inventory schema (`check-backports-inventory` step).
- Runs a **dry run** of the branch creation (`trigger-backport-dryrun` step), verifying the commit exists and the branch does not already exist, without pushing anything.

By default, the created branch only contains the target package — all other packages in `packages/` are removed to keep the branch lean.

The pipeline can also be triggered manually from the UI (restricted to members of the `ecosystem` team). The following parameters can be configured when triggering manually:
- **REMOVE_OTHER_PACKAGES**: If `true`, only the target package is kept in the `packages/` directory; all others are removed. Default: `true`.

More information about this pipeline and how to create these hotfixes in:
https://www.elastic.co/guide/en/integrations-developer/current/developer-workflow-support-old-package.html

## Feature branches

`feature/*` branches are long-lived branches used for developing larger features before merging into `main`. They follow the same CI process as Pull Requests, ensuring all checks pass before code is integrated.

- Every push to a `feature/*` branch triggers the main CI pipeline (https://buildkite.com/elastic/integrations), running the same package tests as a regular Pull Request.
- Pull Requests targeting a `feature/*` branch also trigger CI checks, so all changes must pass CI before being merged into the feature branch.
- Intermediate builds are cancelled or skipped when new commits arrive, consistent with `backport-*` branches.
- Changeset detection works the same as for `backport-*` branches: only packages modified since the last successful build are tested. On the first push to a new `feature/*` branch, the merge-base with `origin/main` is used to find commits exclusive to the branch — packages are tested only if those commits contain changes under `packages/`; if only CI infrastructure files changed, no package tests are run.
- Publishing is **not** triggered for `feature/*` branches. Packages are published only when PRs are merged into `main` or `backport-*` branches.
