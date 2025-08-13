---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/elastic-package.html
---

# elastic-package reference [elastic-package]

`elastic-package` is a command line tool, written in Go, used for developing Elastic packages. It can help you lint, format, test, build, and promote your packages.


## Get started [elastic-package-start]

1. Download and build the latest main of elastic-package binary:

    ```bash
    git clone https://github.com/elastic/elastic-package.git
    make build
    ```

    ::::{tip}
    Make sure that you’ve correctly set up the [`$GOPATH` and `$PATH`](https://golang.org/doc/gopath_code.md#GOPATH) environment variables. `elastic-package` must be accessible from your `$PATH`.
    ::::

2. Change into the directory of the package under development:

    ```bash
    cd my-package
    ```

3. Run the `help` command to see available commands

    ```bash
    elastic-package help
    ```



## Command reference [elastic-package-command-reference]

The following `elastic-package` commands are available. For more details on a specific command, run `elastic-package help <command>`.

Some commands have a *global context*, meaning that you can execute them from anywhere. Other commands have a *package context*; these must be executed from somewhere under a package root folder, and the command will only operate on the contents of that package.


### `elastic-package help` [_elastic_package_help]

*Context: global*

Use this command to list all commands available under `elastic-package` and a brief description of what each command does.


### `elastic-package benchmark` [_elastic_package_benchmark]

*Context: package*

Use this command to run benchmarks on a package. Currently, the following types of benchmarks are available:

- [Pipeline benchmarks](https://github.com/elastic/elastic-package/blob/main/docs/howto/pipeline_benchmarking.md)
- [System benchmarks](https://github.com/elastic/elastic-package/blob/main/docs/howto/system_benchmarking.md)
- [Rally benchmarks](https://github.com/elastic/elastic-package/blob/main/docs/howto/pipeline_benchmarking.md)


### `elastic-package build` [_elastic_package_build]

*Context: package*

Use this command to build a package. Currently, it supports only the "integration" package type.

Built packages are stored in the "build/" folder located at the root folder of the local Git repository checkout that contains your package folder. The command will also render the README file in your package folder if a corresponding template file present in `_dev/build/docs/README.md`. All `_dev` directories under your package will be omitted.

Built packages are served up by the {{package-registry}} running locally (see "elastic-package stack"). Therefore, if you want a local package to be served up by the local {{package-registry}}, make sure to build that package first using "elastic-package build".

You can also publish built packages to the global package registry service.

### `elastic-package changelog` [_elastic_package_changelog]

*Context: package*

Use this command to work with the changelog of the package.

You can use this command to modify the changelog following the expected format and good practices.
This can be useful when introducing changelog entries for changes done by automated processes.

### `elastic-package check` [_elastic_package_check]

*Context: package*

Use this command to verify if the package is correct in terms of formatting, validation and building.

It will execute the format, lint, and build commands all at once, in that order.


### `elastic-package clean` [_elastic_package_clean]

*Context: package*

Use this command to clean resources used for building the package.

The command will remove built package files (in build/), files needed for managing the development stack (in `~/.elastic-package/stack/development`) and stack service logs (in `~/.elastic-package/tmp/service_logs`).


### `elastic-package completion` [_elastic_package_completion]

*Context: global*

Use this command to output shell completion information.

The command output shell completions information (for `bash`, `zsh`, `fish` and `powershell`). The output can be sourced in the shell to enable command completion.

Run `elastic-package completion` and follow the instruction for your shell.


### `elastic-package create` [_elastic_package_create]

*Context: global*

Use this command to create a new package or add more data streams.

The command can help bootstrap the first draft of a package using an embedded package template. Then, you can use it to extend the package with more data streams.

For details on creating a new package, review the [HOWTO guide](https://github.com/elastic/elastic-package/blob/main/docs/howto/create_new_package.md).


### `elastic-package dump` [_elastic_package_dump]

*Context: global*

Use this command as an exploratory tool to dump resources from Elastic Stack (objects installed as part of package and agent policies).


### `elastic-package edit` [_elastic_package_edit]

*Context: package*

Use this command to edit assets relevant for the package, e.g. Kibana dashboards.


### `elastic-package export` [_elastic_package_export]

*Context: package*

Use this command to export assets relevant for the package, e.g. {{kib}} dashboards.


### `elastic-package format` [_elastic_package_format]

*Context: package*

Use this command to format the package files.

The formatter supports JSON and YAML format and skips "ingest_pipeline" directories as it’s hard to correctly format Handlebars template files. As a result, formatted files are overwritten.


### `elastic-package install` [elastic-package-install]

*Context: package*

Use this command to upload and install a package in {{kib}}.

Starting with Kibana version `8.7.0`, packages do not need to be exposed in the Package Registry to be installed. Instead, they can be upload as zip files built using the `elastic-package build` command.

1. Ensure you’ve validated your package. Before building, validate the package by running the `elastic-package check` command.
2. Use either the `--zip` parameter to install a specific zip file or the `install` command to build the package and upload the built zip file to Kibana.


#### Install with `--zip` [_install_with_zip]

Install a zipped package. This method relies on Package Registry.

```shell
elastic-package stack up -d
elastic-package install --zip /home/user/Coding/work/integrations/build/packages/elastic_package_registry-0.0.6.zip -v
```


#### Install with `elastic-package install` [_install_with_elastic_package_install]

Build and upload a zipped package without relying on Package Registry.

```shell
elastic-package stack up -v -d
elastic-package install -v
```


#### Customization [_customization]

Package installation can be customized to be installed in other Kibana instances with the following variables:

* `ELASTIC_PACKAGE_KIBANA_HOST`
* `ELASTIC_PACKAGE_ELASTICSEARCH_USERNAME`
* `ELASTIC_PACKAGE_ELASTICSEARCH_PASSWORD`
* `ELASTIC_PACKAGE_CA_CERT`

For example:

```bash
export ELASTIC_PACKAGE_KIBANA_HOST="https://test-installation.kibana.test:9243"
export ELASTIC_PACKAGE_ELASTICSEARCH_USERNAME="elastic"
export ELASTIC_PACKAGE_ELASTICSEARCH_PASSWORD="xxx"
# if it is a public instance, this variable should not be needed
export ELASTIC_PACKAGE_CA_CERT=""

elastic-package install --zip elastic_package_registry-0.0.6.zip -v
```


#### Older versions [_older_versions]

For versions of Kibana `<8.7.0`, the package must be exposed via the Package Registry. In case of development, this means that the package should be built previously and then the Elastic stack must be started. Or, at least, the `package-registry` service needs to be restarted in the Elastic stack:

```bash
elastic-package build -v
elastic-package stack up -v -d  # elastic-package stack up -v -d --services package-registry
elastic-package install -v
```

To install the package in {{kib}}, the command uses {{kib}} API. The package must be exposed via the {{package-registry}}.


### `elastic-package links` [_elastic_package_links]

*Context: global*

Use this command to manage linked files in the repository.


### `elastic-package lint` [_elastic_package_lint]

*Context: package*

Use this command to validate the contents of a package using the package specification (see: [https://github.com/elastic/package-spec](https://github.com/elastic/package-spec)).

The command ensures that the package aligns with the package spec and that the README file is up-to-date with its template (if present).


### `elastic-package profiles` [_elastic_package_profiles]

*Context: global*

Use this command to add, remove, and manage multiple config profiles.

Individual user profiles appear in ~/.elastic-package/stack and contain all the config files needed by the "stack" subcommand. Once a new profile is created, it can be specified with the -p flag, or the ELASTIC_PACKAGE_PROFILE environment variable. User profiles are not overwritten on an upgrade of elastic-stack and can be freely modified to allow for different stack configs.


### `elastic-package promote` [_elastic_package_promote]

*Context: global*

Use this command to move packages between the {{package-registry}} snapshot, staging, and production stages.

This command is intended primarily for use by administrators.

It allows for selecting packages for promotion and opens new pull requests to review changes. However, please be aware that the tool checks out an in-memory Git repository and switches over branches (snapshot, staging and production), so it may take longer to promote a larger number of packages.


### `elastic-package publish` [_elastic_package_publish]

*Context: package*

Use this command to publish a new package revision.

The command checks if the package has already been published (whether it’s present in the snapshot/staging/production branch or open as pull request). If the package revision hasn’t been published, it will open a new pull request.

### `elastic-package report` [_elastic_package_report]

*Context: package*

Use this command to generate various reports relative to the packages. Currently, the following types of reports are available:

#### Benchmark report for Github

These report will be generated by comparing local benchmark results against ones from another benchmark run.
The report will show performance differences between both runs.

It is formatted as a Markdown Github comment to use as part of the CI results.

### `elastic-package service` [_elastic_package_service]

*Context: package*

Use this command to boot up the service stack that can be observed with the package.

The command manages the lifecycle of the service stack defined for the package (`_dev/deploy`) for package development and testing purposes.


### `elastic-package stack` [_elastic_package_stack]

*Context: global*

Use this command to spin up a Docker-based {{stack}} consisting of {{es}}, {{kib}}, and the {{package-registry}}. By default, the latest released version of the {{stack}} is spun up, but it is possible to specify a different version, including SNAPSHOT versions.

For details on connecting the service with the {{stack}}, see the [service command](https://github.com/elastic/elastic-package/blob/main/README.md#elastic-package-service).


### `elastic-package status [package]` [_elastic_package_status_package]

*Context: package*

Use this command to display the current deployment status of a package.

If a package name is specified, then information about that package is returned. Otherwise, this command checks if the current directory is a package directory and reports its status.


### `elastic-package test` [_elastic_package_test]

*Context: package*

Use this command to run tests on a package. Currently, the following types of tests are available:


#### Asset Loading Tests [_asset_loading_tests]

These tests ensure that all the {{es}} and {{kib}} assets defined by your package get loaded up as expected.

For details on running asset loading tests for a package, see the [HOWTO guide](https://github.com/elastic/elastic-package/blob/main/docs/howto/asset_testing.md).


#### Pipeline Tests [_pipeline_tests]

These tests allow you to exercise any Ingest Node Pipelines defined by your packages.

For details on how configuring a pipeline test for a package, review the [HOWTO guide](https://github.com/elastic/elastic-package/blob/main/docs/howto/pipeline_testing.md).


#### Static Tests [_static_tests]

These tests allow you to verify if all static resources of the package are valid, e.g. if all fields of the sample_event.json are documented.

For details on running static tests for a package, see the [HOWTO guide](https://github.com/elastic/elastic-package/blob/main/docs/howto/static_testing.md).


#### System Tests [_system_tests]

These tests allow you to test a package ability for ingesting data end-to-end.

For details on configuring and running system tests, review the [HOWTO guide](https://github.com/elastic/elastic-package/blob/main/docs/howto/system_testing.md).

#### Policy Tests [_policy_tests]

These tests allow you to test different configuration options and the policies they generate, without needing to run a full scenario.

For details on how to configure and run policy tests, review the [HOWTO guide](https://github.com/elastic/elastic-package/blob/main/docs/howto/policy_testing.md).

### `elastic-package uninstall` [_elastic_package_uninstall]

*Context: package*

Use this command to uninstall the package in {{kib}}.

To uninstall the package in {{kib}}, the command uses the {{kib}} API. The package must be exposed via the {{package-registry}}.


### `elastic-package version` [_elastic_package_version]

*Context: global*

Use this command to print the version of elastic-package that you have installed. This command is especially useful when reporting bugs.

