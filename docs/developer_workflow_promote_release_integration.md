# Developer workflow: promote the integration

## Prerequisites

* `elastic-package` (builder tool) installed - follow the [Getting started](https://github.com/elastic/elastic-package#getting-started) guide to install the tool.
* There is a PR open to the [Package Storage/snapshot](https://github.com/elastic/package-storage/tree/snapshot/packages) with your built integration. This will be done automatically by the Integrations repository CI when it detects an unreleased version of your package in the Integrations repository.
* You have a fork of `https://github.com/elastic/package-storage` in your
  account.

## Steps

1. Please review this PR on your own and if the CI is happy, merge it.
2. Release changes to the stage using [1-click Jenkins form](https://beats-ci.elastic.co/job/Ingest-manager/job/release-distribution/build?delay=0sec) (need to be signed in).

3. If you're happy with the package, tested with Kibana and generally it's fine - promote your packages to the staging or production:

    ```bash
    elastic-package promote
    ```
    
    The tool will open 2 PRs (promote and delete) to the package-storage: target and source branches.
    
    Please review both PRs on your own, check if CI is happy and merge - first target, then source. Once any PR is merged,
    the CI will kick off a job to bake a new Docker image of package-storage ([tracking](https://beats-ci.elastic.co/job/Ingest-manager/job/package-storage/)).
    Ideally the "delete" PR should be merged once the CI job for "promote" is done, as the Docker image of previous stage
    [depends on the later one](https://github.com/elastic/package-storage/blob/snapshot/Dockerfile#L5).

4. Use the 1-click from point 2. to release new revision of the package-storage.
