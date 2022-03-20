# Fine-tune the integration

## Motivation

Most of migration work has been done by the `import-beats` script, but there're tasks that require developer's
interaction.

It may happen that your integration misses a screenshot or an icon, it's a good moment to add missing resources to
Beats/Kibana repositories and re-import the integration (idempotent).

## Checklist

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
    in the `package/<integration-name>/_dev/build/docs/README.md`. If the directory doesn't exist, please create it.

    Review the MySQL docs template to see how to use template functions (e.g. `{{fields "data-stream-name"}}`).
    If the same data stream name is used in both metrics and logs, please add `-metrics` and `-logs` in the template. For example, `elb` is a data stream for log and also a data stream for metrics. In README.md template, `{{fields "elb_logs"}}` and `{{fields "elb_metrics"}}` are used to separate them.

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

    - ecs.yml: ECS compliant fields that are used by this particular data stream.
    - package-fields.yml: Package level fields that are used by this particular data stream, which does not exist under `<integration-package-name>.<data-stream-name>`.
    - fields.yml: Dataset level fields that are specific to this particular data stream, and non ECS compliant.


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
    (path: `data stream/<data-stream-name>/manifest.yml`).

    It may happen that some of them in different data streams are simply duplicates or concern the same setting, which
    will be always equal (e.g. MySQL username, password). Keep in mind that two data streams may have the same configuration
    option, but different values (e.g. `period`, `paths`), hence can't be compacted.

    To sum up, compacting takes down from the user the necessity to setup the same configuration option few times (one
    per data stream).

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
    content manually basing on already migrated integrations (e.g. [MySQL integration](https://github.com/elastic/integrations/blob/main/packages/mysql/_dev/build/docs/README.md))
    or copy them once managed to run whole setup with real agent.

12. Kibana: use `stream.data stream` field instead of `event.data stream`.

    Using `stream.data stream` instead of `event.data stream` also makes queries a lot more efficient as this is a
    `constant_keyword`. Make sure that dashboards in your package don't use the `event.data stream` field. If so,
    simply replace them with the more efficient one.
