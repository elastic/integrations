# Developer workflow: build and test the integration

## Prerequisites

* `elastic-package` (builder tool) installed - follow the [Getting Started Guide](https://github.com/elastic/elastic-package#getting-started) guide to install the tool.
* If you don't understand the `elastic-package` command or would like to learn more about it, try the `help` switch, e.g. `elastic-package stack up --help`.

## Steps

I assume that you've selected a product or service from which you'd like to collect logs and metrics. If this is your
first interaction with Integrations or packages, I suggest to review existing Integrations in the Fleet UI and focus on
available UI controls, labels, icons, screenshots. The goal is to meet current standards and practices and apply them
to your new integration.

Let's bring up the Elastic stack:

```bash
elastic-package stack up -v -d
```

Navigate to the [Integrations](http://localhost:5601/app/fleet#/integration) page, try to add an integration to the default
policy and review the forms. Good example integrations to look at are "Nginx", "Apache", and "Nats". After you have
familiarized yourself with some existing integrations you are ready to create your own.

### Bootstrap New Integration Package

The `elastic-package create` command is used to bootstrap new integrations and
new data streams. Let's create a new integration package:

```bash
cd packages
elastic-package create package
Create a new package
? Package name: demo_example
? Version: 0.0.1
? Package title: Demo
? Description: This is a demo!
? Categories: security
? Release: experimental
? Kibana version constraint: ^7.15.1
? Github owner: elastic/integrations
New package has been created: demo_example
Done
```

Respond to the prompts, and then it creates your package in `package/<package
name>`. You can change any of the answers later by modifying the generated
`manifest.yml`.

The generated integration package does not have any data streams yet so it
cannot collect any logs/metrics. Let's add a data stream to the package for
collecting logs.

```bash
cd demo_example
elastic-package create data-stream
Create a new data stream
? Data stream name: log
? Data stream title: Example Logs
? Type: logs
New data stream has been created: log
Done
```

Respond to the prompts and your new data stream will be created in
`packages/<package name>/<data stream name>`. Now you can customize the data
stream with the appropriate Elastic Agent config, Elasticsearch Ingest Node
pipelines, and field definitions for the Elasticsearch index templates.

### Build

Now, it's the moment to build the package:

```bash
elastic-package build
```

... and recycle the package-registry Docker container (run from inside of the integration directory):

```bash
elastic-package stack up -v -d --services package-registry
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

The `elastic-package` tool supports multiple types of tests - pipeline, system, assets. Follow up on the specific topic
using the tool's [documentation](https://github.com/elastic/elastic-package/tree/master/docs/howto).

### Open a PR

Prior to opening a PR, you must sign the [elastic contributor agreement](https://www.elastic.co/contributor-agreement) if you haven't already.

If you think that you've finished work on your integration, you've verified that it collects data, and you've written some tests,
you can [open a PR](https://github.com/elastic/integrations/compare) to include your integration in the [Integrations](https://github.com/elastic/integrations) repository.
The CI will verify if your integration is correct (`elastic-package check`) - a green status is a must.

Feel free to merge the PR once you receive an approval from the Integrations team.

### Remember to bump up the version

When the PR is merged, the CI will kick off a build job for the main branch, which can release your integration to
the package-storage. It means that it will open a PR to the [Package Storage/snapshot](https://github.com/elastic/package-storage/tree/snapshot/packages) with
the built integration if only the package version doesn't already exist in the storage (hasn't been released yet).

When you are ready for your changes in the integration to be released, remember to bump up the package version.
It is up to you, as the package developer, to decide how many changes you want to release in a single version.
For example, you could implement a change in a PR and bump up the package version in the same PR. Or you could
implement several changes across multiple PRs and then bump up the package version in the last of these PRs
or in a separate follow up PR.
