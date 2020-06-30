# Contributing

This page is intended for contributors to the registry and packages.

## Definitions

### Package

A package contains the dashboards, visualisations, and configurations to monitor the logs and metrics of a particular technology or group of related services, such as “MySQL”, or “System”.

The package consists of:

* Name
* Zero or more dashboards and visualisations and Canvas workpads
* Zero or more ML job definitions
* Zero or more dataset templates

The package is versioned.

### Integration

An integration is a specific type of a _package_ defining datasets used to observe the same product (logs and metrics).

### Dataset Template

A dataset template is part of a package and contains all the assets which are needed to create a dataset. Example for assets are: ingest pipeline, agent config template, ES index template, ...

Dataset templates are inside the package directory under `dataset`.

The dataset template consists of:

* An alias templates (or the fields.yml to create it)
* Zero or more ingest pipelines
* An Elastic Agent config template

### Migration from Beats

A defined importing procedure used to transform both Filebeat and Metricbeat modules, related to
the same observed product, into a single integration. The integration contains extracted dataset configuration of beat
modules, hence no modules are required to exist anymore.

## Package structure

### Elements

Link: https://github.com/elastic/package-registry/blob/master/ASSETS.md

### Reference package: mysql

Link: https://github.com/elastic/package-registry/tree/master/packages/mysql

The MySQL integration was the first integration built using the [import-beats](https://github.com/elastic/integrations/tree/master/dev/import-beats) script.
The script imported filesets and metricsets from both MySQL modules, and converted them to a package.

The MySQL integration contains all parts that should be present (or are required) in the integration package.

After using the _import-beats_ script, the integration has been manually adjusted and extended with dedicated docs.

## Create a new integration

This section describes steps required to build a new integration. If you plan to prepare the integration
with a product unsupported by [Beats](https://github.com/elastic/beats), feel free to skip the section about importing
existing modules.

### Import from existing modules

The import procedure heavily uses on the _import-beats_ script. If you are interested how does it work internally,
feel free to review the script's [README](https://github.com/elastic/integrations/tree/master/dev/import-beats/README.md).

1. Create an issue in the [integrations](https://github.com/elastic/integrations) to track ongoing progress with
    the integration (especially manual changes).

    Focus on the one particular product (e.g. MySQL, ActiveMQ) you would like to integrate with.
    Use this issue to mention every manual change that has been applied. It will help in adjusting the `import-beats`
    script and reviewing the integration.

2. Prepare the developer environment:
    1. Clone/refresh the following repositories:
        * https://github.com/elastic/beats
        * https://github.com/elastic/ecs
        * https://github.com/elastic/eui
        * https://github.com/elastic/kibana

       Make sure you don't have any manual changes applied as they will reflect on the integration.
    2. Clone/refresh the Elastic Integrations to always use the latest version of the script:
        * https://github.com/elastic/integrations
    3. Make sure you've the `mage` tool installed:
        ```bash
       $ go get -u -d github.com/magefile/mage
       ```
3. Boot up required dependencies:
    1. Elasticseach instance:
        * Kibana's dependency
    2. Kibana instance:
        * used to migrate dashboards, if not available, you can skip the generation (`SKIP_KIBANA=true`)

    _Hint_. There is dockerized environment in beats (`cd testing/environments`). Boot it up with the following command:
    `docker-compose -f snapshot.yml up --force-recreate`.
4. Create a new branch for the integration in `integrations` repository (diverge from master).
5. Run the command: `mage ImportBeats` to start the import process.

    The outcome of running the `import-beats` script is directory with refreshed and updated integrations.

    It will take a while to finish, but the console output should be updated frequently to track the progress.
    The command must end up with the exit code 0. Kindly please to open an issue if it doesn't.

    Generated packages are stored by default in the `packages` directory. Generally, the import process
    updates all of the integrations, so don't be surprised if you notice updates to multiple integrations, including
    the one you're currently working on (e.g. `packages/foobarbaz`). You can either commit this changes
    or leave them for later.

    If you want to select a subgroup of packages, set the environment variable `PACKAGES` (comma-delimited list):

    ```bash
   $ PACKAGES=aws,cisco mage ImportBeats
    ```

### Fine-tune the integration

#### Motivation

Most of migration work has been done by the `import-beats` script, but there're tasks that require developer's
interaction.

It may happen that your integration misses a screenshot or an icon, it's a good moment to add missing resources to
Beats/Kibana repositories and re-import the integration (idempotent). 

#### Checklist

The order of action items on the checklist is advised to prevent the contributor from repeating some actions (fixing
what's been already fixed, as the script has overridden part of it).

1. Add icon if missing.

    The integration icons are presented in different places in Kibana, hence it's better to define custom icons to make
    the UI easier to navigate.

    As the `import-beats` script looks for icons in Kibana and EUI repositories, add an icon to the first one the same
    way as for tutorial resources (Kibana directory: `src/legacy/core_plugins/kibana/public/home/tutorial_resources/logos/`).

2. Add screenshot if missing.

    The Kibana Integration Manager shows screenshots related with the integration. Screenshots present Kibana
    dashboards visualizing the metric/log data.

    The `import-beats` script finds references to screenshots mentioned in `_meta/docs.asciidoc` and copies image files
    from the Beats directories:
    * `metricbeat/docs/images`
    * `filebeat/docs/images`

3. Improve/correct spelling product names.

    The correct spelling of product names simply makes better impression. The `import-beats` scripts uses the `fields.yml`
    file as the source of the correct spelling (`title` property), e.g. Mysql - MySQL, Nginx - NGINX, Aws - AWS.

    Keep in mind that this step requires reimporting package contents.

4. Write README template file for the integration.

    The README template is used to render the final README file including exported fields. The template should be placed
    in the `dev/import-beats-resources/<integration-name>/docs/README.md`.

    Review the MySQL docs template to see how to use template functions (e.g. `{{fields "dataset-name"}}`). 
    If the same dataset name is used in both metrics and logs, please add `-metrics` and `-logs` in the template. For example, `elb` is a dataset for log and also a dataset for metrics. In README.md template, `{{fields "elb_logs"}}` and `{{fields "elb_metrics"}}` are used to separate them.

5. Review fields file and exported fields in docs.

    The goal of this action item is to verify if produced artifacts are correct.

    The fields files (package-fields.yml, fields.yml and ecs.yml) in the package were created from original fields.yml
    files (that may contain ECS schema fields) and fields.epr.yml (defining some other fields used in the ingest
    pipeline). It may happen that original sources have a typo, bad description or misses a field definition.
    The sum of fields in all present files should contain only fields that are really used, e.g. not all existing ECS
    fields.

    It may happen that the ingest pipeline uses fields abstracted from ECS, but not mentioned in `fields.yml`.
    Integrations should contain these fields and also have them documented.

    The fields for an integration package are divided into the following three files:

    - ecs.yml: ECS compliant fields that are used by this particular dataset.
    - package-fields.yml: Package level fields that are used by this particular dataset, which does not exist under `<integration-package-name>.<dataset-name>`.
    - fields.yml: Dataset level fields that are specific to this particular dataset, and non ECS compliant.


    See the PR https://github.com/elastic/beats/pull/17895 to understand how to add them to Beats (e.g. `event.code`,
    `event.provider`) using the `fields.epr.yml` file.

6. Metricbeat: add missing configuration options.

   The `import-beats` script extracts configuration options from Metricbeat module's `_meta` directory. It analyzes
   the configuration files and selects options based on enabled metricsets (not commented). If you notice that some
   configuration options are missing in your package's manifest files, simply create the `config.epr.yml` file with all
   required options.

   Sample PR: https://github.com/elastic/beats/pull/17323

7. Review _titles_ and _descriptions_ in manifest files.

    Titles and descriptions are fields visualized in the Kibana UI. Most users will use them to see how to configure
    the integration with their installation of a product or to how to use advanced configuration options.

8. Compact configuration options (vars).

    Currently, all configuration options are set by the `import-beats` script on the stream level
    (path: `dataset/<dataset-name>/manifest.yml`).

    It may happen that some of them in different datasets are simply duplicates or concern the same setting, which
    will be always equal (e.g. MySQL username, password). Keep in mind that two datasets may have the same configuration
    option, but different values (e.g. `period`, `paths`), hence can't be compacted.

    To sum up, compacting takes down from the user the necessity to setup the same configuration option few times (one
    per dataset).

9. Define all variable properties.

    The variable properties customize visualization of configuration options in the Kibana UI. Make sure they're
    defined in all manifest files.

```yaml
    vars:
      - name: paths
        required: true
        show_user: true
        title: Access log paths
        description: Paths to the nginx access log file.
        type: text
        multi: true
        default:
          - /var/log/nginx/access.log*
```

**required** - option is required

**show_user** - don't hide the configuration option (collapsed menu)

**title** - human readable variable name

**description** - variable description (may contain some details)

**type** - field type (according to the reference: text, password, bool, integer)

**multi** - the field has mutliple values.

10. Review stream configuration.

    Due to changed templating engine from a standard Golang one to [handlebars](https://handlebarsjs.com/), it may be
    hard to automatically convert the Filebeat input configuration (nested variables, many representations, conditions,
    loops). Kindly please to review the output stream configuration and review potential bugs.

11. Update docs template with sample events.

    The events collected by the agent slightly differ from original, Metricbeat's and Filebeat's, ones. Adjust the event
    content manually basing on already migrated integrations (e.g. [MySQL integration](https://github.com/elastic/integrations/blob/master/dev/import-beats-resources/mysql/docs/README.md))
    or copy them once managed to run whole setup with real agent.

12. Kibana: use `stream.dataset` field instead of `event.dataset`.

    Using `stream.dataset` instead of `event.dataset` also makes queries a lot more efficient as this is a
    `constant_keyword`. Make sure that dashboards in your package don't use the `event.dataset` field. If so,
    simply replace them with the more efficient one.

## Testing and validation

### Run the whole setup

1. Build `public` directory with package data:
   ```bash
   $ mage build
   ```

2. Start testing environment:
   ```bash
   $ cd testing/environments
   $ docker-compose -f snapshot.yml up
   ```

   The command will boot up a docker cluster with Elasticsearch, Kibana and Package Registry. The Package Registry
   has a volume mounted with the `public` directory. After every time you rebuild packages (`mage build`), all
   adjustments in packages will be propagated to the registry.

3. Verify that your integration is available (in the right version), e.g. MySQL: http://localhost:8080/search?package=mysql (use 
   `experimental=true` parameter if the package is in experimental version. Alternatively set `release` to `beta` or higher in your
   package's `manifest.yml`, if appropriate.)

    ```json
    [
      {
        "description": "MySQL Integration",
        "download": "/epr/mysql/mysql-0.0.1.tar.gz",
        "icons": [
          {
            "src": "/package/mysql/0.0.1/img/logo_mysql.svg",
            "title": "logo mysql",
            "size": "32x32",
            "type": "image/svg+xml"
          }
        ],
        "name": "mysql",
        "path": "/package/mysql/0.0.1",
        "title": "MySQL",
        "type": "integration",
        "version": "0.0.1"
      }
    ]
    ```

4. Build agent code:
    ```bash
   $ cd $GOPATH/src/github.com/elastic/beats/x-pack/elastic-agent
   $ PLATFORMS=darwin mage package
    ```

   If your are building on a Mac and you get the following error, you may ignore it. The package has built successfully anyway.

    ```
    xcode-select: error: tool 'xcodebuild' requires Xcode, but active developer directory '/Library/Developer/CommandLineTools' is a command line tools instanceError: running "xcodebuild build -project beats-preference-pane.xcodeproj -alltargets -configuration Release CODE_SIGN_IDENTITY= CODE_SIGNING_REQUIRED=NO" failed with exit code 1
    ```

   Unpack the distribution you'd like to use (e.g. tar.gz):
   ```bash
   $ cd build/distributions/
   $ tar xzf elastic-agent-8.0.0-darwin-x86_64.tar.gz
   $ cd elastic-agent-8.0.0-darwin-x86_64/
   ```

5. Enroll the agent and start it:

   Use the "Enroll new agent" option in the Kibana UI (Ingest Manager -> Fleet -> Create user and enable Fleet) and run a similar command:

   ```bash
   $ ./elastic-agent enroll http://localhost:5601/rel cFhNVlZIRUIxYjhmbFhqNTBoS2o6OUhMWkF4SFJRZmFNZTh3QmtvR1cxZw==
   $ ./elastic-agent run
   ```

   The `elastic-agent` will start two other processes - `metricbeat` and `filebeat`.

6. Run the product you're integrating with (e.g. a docker image with MySQL).

7. Install package.

    Click out the configuration in the Kibana UI, deploy it and wait for the agent to pick out the updated configuration.

8. Navigate with Kibana UI to freshly installed dashboards, verify the metrics/logs flow.

## Tips for building integrations

The section offers a set of tips for developers to improve integrations that they're working on. It combines hints, guidelines,
recommendations and tricks. Please consider this section as a live document that may evolve in the future, depending
on the business or technical requirements for the entire platform (Elastic Package Registry, Elastic Agent and Kibana).

### New integrations

#### Manifest files

1. Set the initial version to `0.1.0`.

   Tagging the integration with a lower version, like `0.0.1`, means that it's at very early stage and most likely
   it doesn't work at all. It might be partially developed.

2. Set the initial release to `beta`.

   If you working on the new integration that will be release in the next release cycle, you can tag it with `beta`.
   Otherwise, feel free to stick with the `experimental` tag.

### All integrations

#### Code reviewers

1. Ping "Team:Integrations".

   Use the team label to notify relevant team members about the incoming pull request.

#### Manifest files

1. Descriptions of configuration options should be as short as possible.

   Remember to keep only the meaningful information about the configuration option.

   Good candidates: references to the product configuration, accepted string values, explanation.

   Bad candidates: *Collect metrics from A, B, C, D,... X, Y, Z datasets.*

2. Descriptions should be human readable.

   Try to rephrase sentences like: *Collect foo_Bar3 metrics*, into *Collect Foo Bar metrics*.

3. Description should be easy to understand.

   Simplify sentences, don't provide information about the input if not required.

   Bad candidate: *Collect application logs (log input)*

   Good candidates: *Collect application logs*, *Collect standard logs for the application*

4. Letter casing is important for screenshot descriptions.

   These descriptions are visualized in the Kibana UI. It would be better experience to have them clean and consistent.

   Bad candidate: *filebeat running on ec2 machine*

   Good candidates: *Filebeat running on AWS EC2 machine*

#### CI

1. Run `mage check` locally.

   Before pushing commits to the repository, verify if the change complete with `mage check`. This command target is
   used by the CI while validating your code changes.

#### Fields

1. Remove empty fields files.

   If you notice that fields file (e.g. `package-fields.yml`) doesn't contain any field definitions or it defines root only,
   feel free to remove it.

   Bad candidate: 
   ```yaml
- name: mypackage.mydataset
  type: group
  release: experimental
```
