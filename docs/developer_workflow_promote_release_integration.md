# Developer workflow: Promote an integration update

## Using Package Storage (V1)

### Prerequisites

* `elastic-package` (builder tool) installed - follow the [Getting started](https://github.com/elastic/elastic-package#getting-started) guide to install the tool.
* There is a PR open to the [Package Storage/snapshot](https://github.com/elastic/package-storage/tree/snapshot/packages) with your built integration. This will be done automatically by the Integrations repository CI when it detects an unreleased version of your package in the Integrations repository.
* You have a fork of `https://github.com/elastic/package-storage` in your
  account.
* Setup a Github token and place the hash in `$HOME/.elastic/github.token`.

### Steps


1. Please review this PR on your own and if the CI is happy, merge it. Your PR will be made against a base branch that corresponds to the stage that you will be pushing this package into for testing/deployment (e.g. "snapshot", "staging", etc). This will be referred to in the following steps as your "target stage".
2. Release changes to the stage using [1-click Jenkins form](https://fleet-ci.elastic.co/job/Ingest-manager/job/release-distribution/build?delay=0sec) (need to be signed in). Remember to wait until the build has finished before triggering a release. Note: triggering a release will push all changes that have been merged to the target stage branch.
3. Test your package update - point a running Kibana at your target stage's [package registry URL](https://github.com/elastic/package-registry#docker) using [the Fleet Kibana settings](https://www.elastic.co/guide/en/kibana/master/fleet-settings-kb.html#fleet-data-visualizer-settings)
4. Once happy with the changes in your target stage, promote your package to the next stage using [the elastic-package tool](https://github.com/elastic/elastic-package).
   ```bash
   elastic-package promote
   ```
   The tool will walk you through some options and open 2 PRs (promote and delete) to the package-storage: target and source branches.

   Please review both PRs on your own, check if CI is happy and merge - first target, then source. Once any PR is merged,
   the CI will kick off a job to bake a new Docker image of package-storage ([tracking](https://fleet-ci.elastic.co/job/Ingest-manager/job/package-storage/)).
   Ideally the "delete" PR should be merged once the CI job for "promote" is done, as the Docker image of previous stage
   [depends on the later one](https://github.com/elastic/package-storage/blob/snapshot/Dockerfile#L5).

4. GOTO Step 2

## Using Package Storage V2

Package Storage V2 is the successor of the [package-storage](https://github.com/elastic/package-storage) Git repository.
You can find more info about this [here](https://github.com/elastic/elastic-package/blob/main/docs/howto/use_package_storage_v2.md#use-package-storage-v2).

This new storage is already set up in this repository. Everytime a new version of a package is merged, that version is built and
published into this storage automatically. Jenkins stage where this step is performed: [Publish to Package Storage V2](../.ci/Jenkinsfile).

This storage is based completely in [semantic versioning](https://semver.org) to release the packages as snapshots, technical previews or stable versions.
More info about the versioning [here](https://github.com/elastic/elastic-package/blob/main/docs/howto/use_package_storage_v2.md#prerelease-and-stable-version).

Considerations until Package Storage V1 is deprecated [here](https://github.com/elastic/elastic-package/blob/main/docs/howto/use_package_storage_v2.md#existing-packages).
