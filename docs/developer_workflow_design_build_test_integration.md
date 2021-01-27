# Developer workflow: build and test the integration

## Prerequisites

* `elastic-package` (builder tool) installed - follow the [Getting started](https://github.com/elastic/elastic-package#getting-started) guide to install the tool. 
* if you don't understand the `elastic-package` command or would like to learn more about it, try the `help` switch, e.g. `elastic-package stack up --help`.

## Steps

I assume that you've selected a product or service from which you'd like to collect logs and metrics. If this is your
first interaction with Integrations or packages, I suggest to review existing Integrations in the Fleet UI.

Let's bring up the Elastic stack:

```bash
elastic-package stack up -v -d
```

Navigate to the [Integrations](http://localhost:5601/app/fleet#/integration) page, try to add an integration to the default
policy, review forms. The good candidate to start your journey are "Nginx", "Apache", "Nats".

Once you selected the donor for your integration, copy the package source, e.g.:

```bash
cd packages
cp -r nginx new_package
```

where `new_package` is the name of your integration.

Review all resources, remove unnecessary ones, adjusts manifests, create new data streams.

### Build

Now, it's the moment to build the package:

```bash
elastic-package build
```

... and recycle the package-registry Docker container (run from inside of the integration directory):

```bash
elastic-package stack up --services package-registry
```

Once the container is recycled, you can refresh the Fleet UI and Kibana will pick up updated packages.

### Lint

You can verify if the package is aligned with the package-spec using:

```bash
elastic-package lint
```

The command will show potential problems with linting and give you a suggestion on how to fix it.

### Format

You can format the package contents (JSON, YML files) with:

```bash
elastic-package format
```

### Export resources

If you're working on Kibana dashboards and would like to export them to local directories, run the following command
(run from inside of the integration directory):

```bash
elastic-package export
```

... and follow TUI steps (dashboard selection).

### Test

The `elastic-package` tool supports multiple levels of testing - pipeline, system, assets. Follow up on the specific topic
using the tool's [documentation](https://github.com/elastic/elastic-package/tree/master/docs/howto).

### Remember to bump up the version

When the PR is merged, the CI will kick off a build job for the master branch, which can release your integration to
the package-storage. It means that it will open a PR to the [Package Storage/snapshot](https://github.com/elastic/package-storage/tree/snapshot/packages) with
the built integration if only the package version doesn't already exist in the storage (hasn't been released yet).

Long story short - if you want your changes in the integration to be released, remember to bump up the package version.

### Open a PR

If you think that you've finished works on your integration, you've verified that it collects data, wrote some tests,
you can [open a PR](https://github.com/elastic/integrations/compare) to include your integration in the [Integrations](https://github.com/elastic/integrations) repository.
The CI will verify if your integration is correct (`elastic-package check`) - a green status is a must.

Feel free to merge the PR once you receive an approval from the Integrations team.