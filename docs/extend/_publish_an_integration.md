---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/_publish_an_integration.html
---

# Publish an integration via Pull Request[_publish_an_integration]

When your integration is done, it’s time to open a PR to include it in the integrations repository. 
Before opening your PR, make sure you have:

1. **Run pre-submission checks**
Run `elastic-package check` to validate formatting, build, and linting. Run `elastic-package format` if files need reformatting.

2. **Add a changelog entry**
Include a `link:` field pointing to your PR. Use the correct type: `enhancement`, `bug-fix`, `breaking-change`, or `deprecation`.

3. **Update CODEOWNERS** (new integrations only)
Add your package to `.github/CODEOWNERS` with the format: `packages/<package_name> @elastic/<team-name>`.

4. **Include test coverage**
Run `elastic-package test` before submitting. Generate `sample_event.json` using `elastic-package test system --generate`.

5. **Bump the package version appropriately**
Use minor version bumps for documentation-only changes and patch bumps for small fixes.

6. **Document breaking changes**
Use `breaking-change` type in changelog and clearly describe impact on existing users. Breaking changes require a major version bump.

   The following changes are considered breaking:

   - **Field type changes**: Changing a field's data type (e.g., `keyword` to `long`, `long` to `keyword`) causes mapping conflicts for existing users
   - **Field removal**: Removing fields that users may depend on in dashboards, alerts, or queries
   - **Field renaming**: Renaming fields breaks existing references (dashboards, saved queries, detection rules)
   - **ECS field collisions**: Removing non-ECS fields from ECS namespaces or changing ECS field mappings
   - **Event value changes**: Changing standardized values (e.g., `event.outcome` from `"Succeeded"` to `"success"`)
   - **Configuration changes**: Requiring new credentials, changing authentication methods, or modifying required settings
   - **Data stream changes**: Splitting, merging, or restructuring data streams
   - **Transform destination changes**: Modifying transform destination indices (requires updating `fleet_transform_version`)
   - **Default behavior changes**: Changing defaults that alter data collection (e.g., deduplication settings, data stream datasets)

7. **Add error handling to ingest pipelines**
Include `tag` fields on processors and use `on_failure` handlers. Follow the standard error message format with `_ingest.on_failure_*` fields.

8. **Write a clear PR title and description**
Use a concise, descriptive title (e.g., `[New Integration] Add Acme Logs integration`). Summarize changes, reference related issues, and ensure documentation is up to date.

::::{tip}
A well-written PR with clear documentation, versioning, and testing instructions will speed up the review and publishing process!
::::


When CI is happy, merge your PR into the integrations repository.

Once the PR with the new version of the package is merged, the required CI pipelines are triggered to release that new version into Package Storage V2 and make them available in https://epr.elastic.co.


::::{tip}
When you are ready for your changes in the integration to be released, remember to bump up the package version. It is up to you, as the package developer, to decide how many changes you want to release in a single version. For example, you could implement a change in a PR and bump up the package version in the same PR. Or you could implement several changes across multiple pull requests and then bump up the package version in the last of these pull requests or in a separate follow up PR.
::::


