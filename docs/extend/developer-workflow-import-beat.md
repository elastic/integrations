---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/developer-workflow-import-beat.html
---

# Import integration from Beats modules [developer-workflow-import-beat]

The import procedure heavily uses on the *import-beats* script. If you are interested how does it work internally, feel free to review the script’s [README](https://github.com/elastic/integrations/tree/main/dev/import-beats/README.md).

1. Create an issue in the [integrations](https://github.com/elastic/integrations) to track ongoing progress with the integration (especially manual changes).

    Focus on the one particular product (e.g. MySQL, ActiveMQ) you would like to integrate with. Use this issue to mention every manual change that has been applied. It will help in adjusting the `import-beats` script and reviewing the integration.

2. Prepare the developer environment:

    1. Clone/refresh the following repositories:

        * [https://github.com/elastic/beats](https://github.com/elastic/beats)
        * [https://github.com/elastic/ecs](https://github.com/elastic/ecs)
        * [https://github.com/elastic/eui](https://github.com/elastic/eui)
        * [https://github.com/elastic/kibana](https://github.com/elastic/kibana)

            Make sure you don’t have any manual changes applied as they will reflect on the integration.

    2. Clone/refresh the Elastic Integrations to always use the latest version of the script:

        * [https://github.com/elastic/integrations](https://github.com/elastic/integrations)

    3. Make sure you’ve the `mage` tool installed:

        ```bash
        $ go get -u -d github.com/magefile/mage
        ```

3. Use the `elastic-package stack up -v -d` command to boot up required dependencies:

    1. Elasticseach instance:

        * Kibana’s dependency

    2. Kibana instance:

        * used to migrate dashboards, if not available, you can skip the generation (`SKIP_KIBANA=true`)

            *Hint*. There is the `elastic-package` cheat sheet available [here](https://github.com/elastic/integrations/blob/main/testing/environments/README.md).

4. Create a new branch for the integration in `integrations` repository (diverge from main).
5. Run the command: `mage ImportBeats` to start the import process (note that the import script assumes the projects checked out in step 2 are at `+../{{project-name}}+`).

    The outcome of running the `import-beats` script is directory with refreshed and updated integrations.

    It will take a while to finish, but the console output should be updated frequently to track the progress. The command should terminate with an exit code of 0. If it doesn’t, please open an issue.

    Generated packages are stored by default in the `packages` directory. Generally, the import process updates all of the integrations, so don’t be surprised if you notice updates to multiple integrations, including the one you’re currently working on (e.g. `packages/foobarbaz`). You can either commit these changes or leave them for later.

    If you want to select a subgroup of packages, set the environment variable `PACKAGES` (comma-delimited list):

    ```bash
    $ PACKAGES=aws,cisco mage ImportBeats
    ```



## Fine tune the integration [_fine_tune_the_integration]

Most of migration work has been done by the `import-beats` script, but there’re tasks that require developer’s interaction.

It may happen that your integration misses a screenshot or an icon, it’s a good moment to add missing resources to Beats/Kibana repositories and re-import the integration (idempotent).


### Checklist [_checklist]

The order of action items on the checklist is advised to prevent the contributor from repeating some actions (fixing what’s been already fixed, as the script has overridden part of it).

1. Add icon if missing.

    The integration icons are presented in different places in Kibana, hence it’s better to define custom icons to make the UI easier to navigate.

    As the `import-beats` script looks for icons in Kibana and EUI repositories, add an icon to the first one the same way as for tutorial resources (Kibana directory: `src/legacy/core_plugins/kibana/public/home/tutorial_resources/logos/`).

2. Add screenshot if missing.

    The Kibana Integration Manager shows screenshots related with the integration. Screenshots present Kibana dashboards visualizing the metric/log data.

    The `import-beats` script finds references to screenshots mentioned in `_meta/docs.asciidoc` and copies image files from the Beats directories:

    * `metricbeat/docs/images`
    * `filebeat/docs/images`

3. Improve/correct spelling product names.

    The correct spelling of product names simply makes better impression. The `import-beats` scripts uses the `fields.yml` file as the source of the correct spelling (`title` property), e.g. Mysql - MySQL, Nginx - NGINX, Aws - AWS.

    Keep in mind that this step requires reimporting package contents.

4. Write README template file for the integration.

    The README template is used to render the final README file including exported fields. The template should be placed in the `package/<integration-name>/_dev/build/docs/README.md`. If the directory doesn’t exist, please create it.

    Review the MySQL docs template to see how to use template functions (e.g. `{{fields "data-stream-name"}}`). If the same data stream name is used in both metrics and logs, please add `-metrics` and `-logs` in the template. For example, `elb` is a data stream for log and also a data stream for metrics. In README.md template, `{{fields "elb_logs"}}` and `{{fields "elb_metrics"}}` are used to separate them.

5. Review fields file and exported fields in docs.

    The goal of this action item is to verify if produced artifacts are correct.

    The fields files (package-fields.yml, fields.yml and ecs.yml) in the package were created from original fields.yml files (that may contain ECS schema fields) and fields.epr.yml (defining some other fields used in the ingest pipeline). It may happen that original sources have a typo, bad description or misses a field definition. The sum of fields in all present files should contain only fields that are really used, e.g. not all existing ECS fields.

    It may happen that the ingest pipeline uses fields abstracted from ECS, but not mentioned in `fields.yml`. Integrations should contain these fields and also have them documented.

    The fields for an integration package are divided into the following three files:

    * ecs.yml: ECS compliant fields that are used by this particular data stream.
    * package-fields.yml: Package level fields that are used by this particular data stream, which does not exist under `<integration-package-name>.<data-stream-name>`.
    * fields.yml: Dataset level fields that are specific to this particular data stream, and non ECS compliant.

    See the PR [https://github.com/elastic/beats/pull/17895](https://github.com/elastic/beats/pull/17895) to understand how to add them to Beats (e.g. `event.code`, `event.provider`) using the `fields.epr.yml` file.

6. Metricbeat: add missing configuration options.

    The `import-beats` script extracts configuration options from Metricbeat module’s `_meta` directory. It analyzes the configuration files and selects options based on enabled metricsets (not commented). If you notice that some configuration options are missing in your package’s manifest files, simply create the `config.epr.yml` file with all required options.

    Sample PR: [https://github.com/elastic/beats/pull/17323](https://github.com/elastic/beats/pull/17323)

7. Review *titles* and *descriptions* in manifest files.

    Titles and descriptions are fields visualized in the Kibana UI. Most users will use them to see how to configure the integration with their installation of a product or to how to use advanced configuration options.

8. Compact configuration options (vars).

    Currently, all configuration options are set by the `import-beats` script on the stream level (path: `data stream/<data-stream-name>/manifest.yml`).

    It may happen that some of them in different data streams are simply duplicates or concern the same setting, which will be always equal (e.g. MySQL username, password). Keep in mind that two data streams may have the same configuration option, but different values (e.g. `period`, `paths`), hence can’t be compacted.

    To sum up, compacting takes down from the user the necessity to setup the same configuration option few times (one per data stream).

9. Define all variable properties.

    The variable properties customize visualization of configuration options in the Kibana UI. Make sure they’re defined in all manifest files.

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

    * **required** - option is required
    * **show_user** - don’t hide the configuration option (collapsed menu)
    * **title** - human readable variable name
    * **description** - variable description (may contain some details)
    * **type** - field type (according to the reference: text, password, bool, integer)
    * **multi** - the field has mutliple values.

10. Review stream configuration.

    Due to changed templating engine from a standard Golang one to [handlebars](https://handlebarsjs.com/), it may be hard to automatically convert the Filebeat input configuration (nested variables, many representations, conditions, loops). Please review the output stream configuration and identify potential bugs.

11. Update docs template with sample events.

    The events collected by the agent slightly differ from the original, Metricbeat and Filebeat, ones. Adjust the event content manually basing on already migrated integrations (e.g. [MySQL integration](https://github.com/elastic/integrations/blob/main/packages/mysql/_dev/build/docs/README.md)) or copy them once managed to run whole setup with real agent.

12. Kibana: use `stream.data stream` field instead of `event.data stream`.

    Using `stream.data stream` instead of `event.data stream` also makes queries a lot more efficient as this is a `constant_keyword`. Make sure that dashboards in your package don’t use the `event.data stream` field. If so, simply replace them with the more efficient one.
