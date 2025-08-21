---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/_publish_an_integration.html
---

# Publish an integration [_publish_an_integration]

When your integration is done, it’s time to open a PR to include it in the integrations repository. Before opening your PR, run:

```bash
elastic-package check
```

The `check` command ensures the package is built correctly, formatted properly, and aligned with the spec. Passing the `check` command is required before adding your integration to the repository.

When CI is happy, merge your PR into the integrations repository.

CI will kick off a build job for the main branch, which can release your integration to the package-storage. It means that it will open a PR to the Package Storage/snapshot with the built integration if only the package version doesn’t already exist in the storage (hasn’t been released yet).


## Promote [_promote]

Now that you’ve tested your integration with {{kib}}, it’s time to promote it to staging or production. Run:

```bash
elastic-package promote
```

The tool will open 2 pull requests (promote and delete) to the package-storage: target and source branches.

Please review both pull requests on your own, check if CI is happy and merge - first target, then source. Once any PR is merged, the CI will kick off a job to bake a new Docker image of package-storage (tracking). Ideally the "delete" PR should be merged once the CI job for "promote" is done, as the Docker image of previous stage depends on the later one.

::::{tip}
When you are ready for your changes in the integration to be released, remember to bump up the package version. It is up to you, as the package developer, to decide how many changes you want to release in a single version. For example, you could implement a change in a PR and bump up the package version in the same PR. Or you could implement several changes across multiple pull requests and then bump up the package version in the last of these pull requests or in a separate follow up PR.
::::


