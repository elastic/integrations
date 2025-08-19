---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/_publish_an_integration.html
---

# Publish an integration via Pull Request[_publish_an_integration]

When your integration is done, it’s time to open a PR to include it in the integrations repository. 
Before opening your PR, make sure you have:

1. Pass all checks
Run:
```bash
elastic-package check
```

This command validates that your package is built correctly, formatted properly, and aligned with the specification. Passing this `check` is required before submitting your integration.

2. Added a new entry into `changelog.yml`
Update the package’s `changelog.yml` with a clear description of your changes for the new version.

3. Bumped the package version
If you are releasing new changes, increment the version in your manifest.yml file. This is required for the package to be published.

4. Wrote clear PR title and description
- Use a concise, descriptive title (e.g., `[New Integration] Add Acme Logs integration`).
- In the PR description, summarize what your integration or change does, list key features or fixes, reference related issues, and provide testing instructions.
- Ensure your documentation, sample events, and tests are included and up to date.

::::{tip}
A well-written PR with clear documentation, versioning, and testing instructions will speed up the review and publishing process!
::::


When CI is happy, merge your PR into the integrations repository.

Once the PR with the new version of the package is merged, the required CI pipelines are triggered to release that new version into Package Storage V2 and make them available in https://epr.elastic.co.


::::{tip}
When you are ready for your changes in the integration to be released, remember to bump up the package version. It is up to you, as the package developer, to decide how many changes you want to release in a single version. For example, you could implement a change in a PR and bump up the package version in the same PR. Or you could implement several changes across multiple pull requests and then bump up the package version in the last of these pull requests or in a separate follow up PR.
::::


