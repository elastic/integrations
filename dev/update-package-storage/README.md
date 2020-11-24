# Update package-storage

The script supports the procedure of releasing changes in the [package-storage](https://github.com/elastic/package-storage/).
Once a developer finishes their work on the integration and bumps up the version of the integration, they can release
changes in the package-storage.

## Prerequisites

### Github authorization token

The tool uses Github API to open a pull request, so it need the Github authorization token. The token must be present
in the `~/.elastic/github.token` file.

_Note: this approach is consistent with the `cherrypick_pr` script for Beats. If you used that one successfully,
the `update-package-storage` should work without any additional changes._

## Principle of operation

Once a developer runs `mage UpdatePackageStorage`, the script iterates over all built integrations (`build/integrations`) in the repository and
checks if the current version has been released (exists in the `package-storage`). If not, it creates a branch for it
in the `package-storage` and copies the content of the unreleased integration. Once changes are pushed to the repository,
it opens a PR with updates to the single integration against the `package-storage`.

Sample PR (fake change, only version bumped up): https://github.com/elastic/integrations/pull/59

## Release updated integrations

1. Bump up the version of the integration (see `manifest.yml` file of the AWS integration: https://github.com/elastic/integrations/blob/master/packages/aws/manifest.yml#L4)
2. Commit changes in integrations and put them in the `master` branch.
3. The CI builds all integrations and executes the mage goal: `mage UpdatePackageStorage`
