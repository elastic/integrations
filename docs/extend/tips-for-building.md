---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/tips-for-building.html
---

# Tips for building integrations [tips-for-building]

This section offers a set of tips for developers to improve integrations they're working on. It combines hints, guidelines, recommendations, and tricks. This document may evolve in the future, depending on business or technical requirements for the entire platform (Elastic Package Registry, Elastic Agent, and Kibana).

## elastic-package [_elastic_package]

[elastic-package](https://github.com/elastic/elastic-package) is a command line tool, written in Go, used for developing Elastic packages. It helps with linting, formatting, testing, and building packages. This is the official builder tool to develop Integrations. See the [Getting started](https://github.com/elastic/elastic-package#getting-started) section to ramp up quickly and review its features.

To use the revision of elastic-package in the correct version (the same one the CI uses), which is defined in `go.mod`, use the following command (in the Integrations repository):

```bash
$ go build github.com/elastic/elastic-package
$ ./elastic-package help
```

## New integrations [_new_integrations]

### Manifest files [_manifest_files]

1. Set the initial version to `0.1.0`.

   Tagging the integration with a lower version, like `0.0.1`, means that it's at a very early stage and most likely doesn't work at all. It might be partially developed.

2. Select one or two categories for the integration.

   The list of available categories is present in the Package Registry source: [https://github.com/elastic/package-registry/blob/1dd3e7c4956f7e34809bb87acae50b2a63cd7ad0/packages/package.go#L29-L55](https://github.com/elastic/package-registry/blob/1dd3e7c4956f7e34809bb87acae50b2a63cd7ad0/packages/package.go#L29-L55)

3. Make sure that the version condition for Kibana is set to `+^7.10.0+` and not `>=7.10.0`. Otherwise, the package is also in 8.0.0 but there is no certainty it will be compatible with >= 8.0.0.

   ```yaml
   conditions:
     kibana.version: '^7.10.0'
   ```

4. Set the proper package owner (either Github team or personal account)

   Good candidates for a team: `elastic/integrations`, `elastic/security-service-integrations`

   Update the `.github/CODEOWNERS` file accordingly.

### Overall Steps

The most important advice to consider is this: gather data first! Start with collecting sample data, or generating data from the appliance (virtual or otherwise). Then, store this data in a file for later reference. This data can be loaded into a Kibana instance to examine and start creating dashboards, and can also be used for pipeline tests.

The process for modifying the repo is to fork it and then create a PR into the repo from a forked copy. After forking, clone it to a development environment.

The `elastic-package create package` command drops the creation into the current directory, so run it from the `packages/` directory, or move the new directory afterward.

```bash
$ cd packages
$ elastic-package create package
Create a new package
? Package type: [Use arrows to move, type to filter]
  input
> integration
? Package name: (new_package)
? Version: (0.0.1)
? License: [Use arrows to move, type to filter]
> Elastic-2.0
  Apache-2.9
  None - I will add a license later.
? Package title: (New Package)
? Description: (This is a new package.)
? Categories: [Use arrows to move, space to select, <right> to all, <left> to none, type to filter]
> [x] custom
? Kibana version constraint: (^8.11.4)
? Required Elastic subscription: [Use arrows to move, type to filter]
> basic
  gold
  platinum
  enterprise
? Github owner: (elastic/integrations)
? Owner type: [Use arrows to move, type to filter]
> elastic - Owned and supported by Elastic
  partner - Vendor-owned with support from Elastic
  community - Supported by the community

New package has been created: new_package
Done
```

This creates a directory structure and default files that will actually work.

```bash
$ cd new_package
$ find .
.
./manifest.yml
./docs
./docs/README.md
./img
./img/sample-screenshot.png
./img/sample-logo.svg
./LICENSE.txt
./changelog.yml
```

A new data-stream can only be created from within a package directory, so make sure to be in the new directory when creating one.

```bash
$ cd new_package
$ elastic-package create data-stream
Create a new data stream
? Data stream name: (new_data_stream)
? Data stream title: (New Data Stream)
? Type: [Use arrows to move, type to filter]
> logs
  metrics
New data stream has been created: new_data_stream
Done
```

This creates a new data-stream directory structure with a default ingest pipeline. All updates exist only in the new `data_stream` directory.

```bash
$ find data_stream
data_stream
data_stream/new_data_stream
data_stream/new_data_stream/elasticsearch
data_stream/new_data_stream/manifest.yml
data_stream/new_data_stream/agent
data_stream/new_data_stream/agent/stream
data_stream/new_data_stream/agent/stream/stream.yml.hbs
data_stream/new_data_stream/fields
data_stream/new_data_stream/fields/base-fields.yml
```

If the data stream is processing logs, naming it `log` is a good idea, as it is short and descriptive.

### Painless example

Sometimes logs are in a format that needs special parsing, like a `key=value msg="something with spaces"` log. Painless scripting can be used to handle this. Here is an example processor:

```yaml
  - script:
      tag: script_kv_parse
      description: Parse key/value pairs from message.
      lang: painless
      source: >-
        ctx["stormshield"] = new HashMap();

        def kvStart = 0;
        def kvSplit = 0;
        def kvEnd = 0;
        def inQuote = false;

        for (int i = 0, n = ctx["message"].length(); i < n; ++i) {
          char c = ctx["message"].charAt(i);
          if (c == (char)'"') {
            inQuote = !inQuote;
          }
          if (inQuote) {
            continue;
          }

          if (c == (char)'=') {
            kvSplit = i;
          }
          if (c == (char)' ' || (i == n - 1)) {
            if (kvStart != kvSplit) {
              def key = ctx["message"].substring(kvStart, kvSplit);
              def value = ctx["message"].substring(kvSplit + 1, i).replace("\"", "");
              ctx["stormshield"][key] = value;
            }

            kvStart = i + 1;
            kvSplit = i + 1;
          }
        }
```

When using functions in painless, the functions need to be defined first. Here's an example of using painless to rename a field, instead of using the `rename` processor:

```yaml
  - script:
      tag: expand_dynamic_fields
      description: Expands some dynamic fields.
      lang: painless
      source: >-
        void handleMove(Map context, String namespace) {
            if (context.containsKey("_temp_") && ! context.containsKey("integration")) {
                context["integration"] = new HashMap();
                context["integration"]["logtype"] = context["_temp_"]["logtype"];
                context["_temp_"].remove("logtype");
            }

            context["integration"][namespace] = context["_temp_"];
            context.remove("_temp_");
        }

        handleMove(ctx, ctx._temp_.logtype);
```

Functions might not be necessary if the code can be refactored to use `forEach` loops.

### `_dev` contents.

The `_dev` directory in the package root and data_stream directories contain files which control some aspects of how the package is built and tested.

#### README

The `docs/README.md` file is generally auto-generated from `_dev/build/docs/README.md`, which also processes some Go format directives for adding field information, sample events and input documentation into the document.

#### Service deployment

For use with system tests, the `_dev/deploy` directory controls how service deployments are run.

An example `_dev/deploy/docker/docker-compose.yml`:
```yaml
version: "2.3"
services:
  integration-udp:
    image: docker.elastic.co/observability/stream:v0.16.0
    volumes:
      - ./sample_logs:/sample_logs:ro
    command: log --start-signal=SIGHUP --delay=5s --addr elastic-agent:5144 -p=udp /sample_logs/integration.log
```

Sample logs can be placed in `_dev/deploy/docker/sample_logs/integration.log`:
```yaml
<13>1 2024-03-08T10:14:08+00:00 integration-1 serverd - - - ﻿id=firewall time="2024-03-08 10:14:08" fw="integration-1" tz=+0000 startime="2024-03-08 10:14:08" error=0 user="admin" address=192.168.197.1 sessionid=1 msg="example syslog line" logtype="server"
<13>1 2024-03-08T10:14:08+00:00 integration-1 serverd - - - ﻿id=firewall time="2024-03-08 10:14:08" fw="integration-1" tz=+0000 startime="2024-03-08 10:14:08" error=0 user="admin" address=192.168.197.1 sessionid=1 msg="example syslog line 2" logtype="server"
```
Together, these two files will start a service which write the sample logs to a UDP socket on port 5144. The Elastic Agent will listen to the data on this port, and process it in a system test.

### Kibana support

To configure the integration through Kibana/Agent/Fleet policy, update the `data_stream/log/manifest.yml` file with input information. Here's an example of how to define parameters and accept variables:

```yaml
title: "Integration logs"
type: logs
streams:
  - input: udp
    title: Integration UDP logs
    description: Collect UDP logs
    template_path: udp.yml.hbs
    vars:
      - name: tags
        type: text
        title: Tags
        multi: true
        required: true
        show_user: false
        default:
          - forwarded
      - name: udp_host
        type: text
        title: Listen Address
        description: The bind address to listen for UDP connections. Set to `0.0.0.0` to bind to all available interfaces.
        multi: false
        required: true
        show_user: true
        default: localhost
      - name: udp_port
        type: integer
        title: Listen Port
        description: The UDP port number to listen on.
        multi: false
        required: true
        show_user: true
        default: 514
      - name: preserve_original_event
        required: true
        show_user: true
        title: Preserve original event
        description: Preserves a raw copy of the original event, added to the field `event.original`.
        type: bool
        multi: false
        default: false
      - name: udp_options
        type: yaml
        title: Custom UDP Options
        multi: false
        required: false
        show_user: false
        default: |
          #read_buffer: 100MiB
          #max_message_size: 50KiB
          #timeout: 300s
        description: Specify custom configuration options for the UDP input.
      - name: processors
        type: yaml
        title: Processors
        multi: false
        required: false
        show_user: false
        description: >
          Processors are used to reduce the number of fields in the exported event or to enhance the event with metadata. This executes in the agent before the logs are parsed. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.

      - name: tz_offset
        type: text
        title: Timezone offset (Country/City or +HH:mm format)
        required: false
        show_user: false
```

This configures the Kibana _Add Integration_ form with the labels, input boxes, descriptions, and also what the `template_path` should be. The `template_path` is a handlebars template file that is used to configure the Agent policy, which is ingested by `filebeat` and will open the configured port and pass information through the syslog processor.

An example file that uses the above configuration can be placed at `data_stream/log/agent/stream/udp.yml.hbs`:

```hbs
host: "{{udp_host}}:{{udp_port}}"
tags:
{{#if preserve_original_event}}
  - preserve_original_event
{{/if}}
{{#each tags as |tag i|}}
  - {{tag}}
{{/each}}
{{#contains "forwarded" tags}}
publisher_pipeline.disable_host: true
{{/contains}}
processors:
- add_locale: ~
{{#if preserve_original_event}}
- copy_fields:
     fields:
       - from: message
         to: event.original
{{/if}}
- syslog:
    field: message
    format: rfc5424
{{#if tz_offset}}
    timezone: "{{tz_offset}}"
{{/if}}
{{#if processors}}
{{processors}}
{{/if}}
```

### More Detail

Pipeline tests are the best way to get the processors working and resolve painless bugs.

When creating fields with mappings to send data into the stack, create a `data_stream/log/fields/fields.yml` file with the nested fields. This information can sometimes be scraped from documentation websites. Here's an example:

```yaml
- name: integration
  type: group
  fields:
    - name: logtype
      type: keyword
      description: The specific type of log this is from.
    - name: alarm
      type: group
      fields:
        - name: action
          type: keyword
          description: 'Behavior associated with the filter rule.  Value: pass or block'
        - name: alarmid
          type: keyword
          description: 'Alarm ID Decimal format. Example: "85"'
        - name: class
          type: keyword
          description: 'Information about the alarms category. String of characters in UTF-8 format. Example: protocol, system, filter'
```

### Kibana dashboard

For the first dashboard, look at existing dashboards for reference. Clone an existing dashboard to use as a starting point. The installed dashboards are `Managed` and cannot be modified directly, but they can be cloned and then edited.

To export a dashboard for inclusion in the integration, use `elastic-package export dashboards`. Name the dashboard with a consistent pattern like `[Integration Name] Overview`. Adding `-- export this one` to the name can make it easier to find when exporting.

When running `elastic-package export dashboards`, it will list all dashboards and allow filtering. Use arrow keys to navigate, spacebar to select, and enter to confirm. The exported dashboard will be saved as a file like `kibana/dashboards/integration-88888888-4444-4444-4444-cccccccccccc.json`, with an actual UUID. Edit the file to remove any `-- export this one` from the title.

If edits to the dashboard are needed later, the file may need to be completely replaced with a new export, as all the UUIDs will change if cloning is required.

When in the dashboard view, create a data filter, otherwise `elastic-package check` will fail the dashboard. Next to the `KQL` search box is a `+` button for this purpose. A good initial filter is `data_stream.dataset : integration-name.log`.

# Pipeline Best Practices

## Error Message Handling

Pipelines should include these processors in the top-level `on_failure` section in the default ingest pipeline:

```yaml
on_failure:
  - set:
      field: event.kind
      value: pipeline_error
  - append:
      field: error.message
      value: 'Processor {{{_ingest.on_failure_processor_type}}} with tag {{{_ingest.on_failure_processor_tag}}} in pipeline {{{_ingest.pipeline}}} failed with message: {{{_ingest.on_failure_message}}}'
```

Any processor that can fail must include a `tag`. Without a tag, the processor that fails cannot be identified in the error message.

```
# With a tag:

Processor conditional with tag grok_test in pipeline default-1711726648444819000 failed with message: cannot access method/field [foo] from a null def reference

# Without a tag:

Processor conditional with tag  in pipeline default-1711726648444819000 failed with message: cannot access method/field [foo] from a null def reference
```

When a processor fails, the `on_failure` handler will be invoked, and two things will occur:

1. The `event.kind` field for the event will be set to `pipeline_error`.
2. A descriptive message will be appended to `error.message`. This message will include the processor type, processor tag, the pipeline in which the error occurred, and a failure message.

Example error messages:

```
Processor grok with tag grok_test in pipeline default-1711726615736144000 failed with message: Provided Grok expressions do not match field value: [abc]
Processor conditional with tag grok_test in pipeline default-1711726648444819000 failed with message: cannot access method/field [foo] from a null def reference
```

While `on_failure` handlers can be added to processors directly, they should not be used for handling error messages. An example of where this is a problem is if the conditional (if statement) of a processor fails. In this case, the `on_failure` for that processor will never run, and instead will fall out to the top-level `on_failure` handler. Instead, they should be used for handling any cleanup if the processor fails, such as removing fields.

## Grok Best Practices

The [grok](https://www.elastic.co/guide/en/elasticsearch/reference/current/grok-processor.html) processor is very powerful, but it can be configured in ways that perform poorly or are difficult to understand.

### Use Dissect When Possible

For simple patterns or patterns where tokens are separated by spaces, consider using the [dissect](https://www.elastic.co/guide/en/elasticsearch/reference/current/dissect-processor.html) processor instead. The dissect processor is usually 2-4 times faster than a grok processor, and can be even faster depending on the complexity of the patterns used.

Consider the grok pattern:

```
^Connection allowed from %{IP:source.ip} to %{IP:destination.ip} at %{TIMESTAMP:event.start}$
```

An equivalent dissect pattern would be:

```
Connection allowed from %{source.ip} to %{destination.ip} at %{event.start}
```

There are cases where dissect cannot be applied, such as:

- Multiple patterns are required
- Some tokens in a pattern are optional
- A token needs to be split into fields

Other notes:

- If replacing grok with dissect, be careful with patterns that extract fields to a certain type. Dissect only extracts to a string, so a [convert](https://www.elastic.co/guide/en/elasticsearch/reference/current/convert-processor.html) processor will be needed.

### Use Simpler Patterns When Possible

In cases where dissect cannot work and grok is still needed, consider using simpler patterns if possible.

Consider this example from the Cisco ASA pipeline. These are the original patterns:

```yaml
patterns:
  - "Group <%{NOTSPACE:source.user.group.name}> User <%{CISCO_USER:source.user.name}> IP <%{IP:source.address}>"
  - "Group %{NOTSPACE:source.user.group.name} User %{CISCO_USER:source.user.name} IP %{IP:source.address}"
pattern_definitions:
  HOSTNAME: "\\b(?:[0-9A-Za-z][0-9A-Za-z-_]{0,62})(?:\\.(?:[0-9A-Za-z][0-9A-Za-z-_]{0,62}))*(\\.?|\\b)"
  IPORHOST: "(?:%{IP}|%{HOSTNAME})"
  CISCO_USER: (?:\*\*\*\*\*|(?:(?:LOCAL\\)?(?:%{HOSTNAME}\\)?%{USERNAME}\$?(?:@%{HOSTNAME})?(?:, *%{NUMBER})?))
```

The patterns after simplification:

```yaml
patterns:
  - '^Group <%{NOTBRACKET:source.user.group.name}> User <%{NOTBRACKET:source.user.name}> IP <%{NOTBRACKET:source.address}>'
  - '^Group %{NOTSPACE:source.user.group.name} User %{NOTSPACE:source.user.name} IP %{NOTSPACE:source.address}'
pattern_definitions:
  NOTBRACKET: "[^<>]+"
```

The first pattern uses angle brackets to contain the values (which can include spaces), so a pattern definition was created that contains all characters except angle brackets. The second pattern uses spaces to delimit fields, so the `NOTSPACE` pattern was used to capture field values. The result of this simplification is that the complicated `HOSTNAME`, `IPORHOST`, and `CISCO_USER` patterns from before can now be removed.

### Grok Patterns Should Be Anchored

Most groks match the entire field. In these cases, the start and end anchors (`^` and `$`) should be used to anchor the pattern against the entire string. This is especially important for performance, since if the pattern cannot match against the string, it will try to find a match within substrings of the field.

# Tips and Tricks

## Commonly Used `elastic-package` Commands

```
elastic-package build
	Builds the package. Also useful for re-rendering the README.

elastic-package check
	Runs the formatter and linter against the package. Also checks if the README has been updated.

Note: Chain build and check together and run them in that order. Check sometimes requires a package being built first.

elastic-package stack up -vd [--version VERSION]
	Bring the stack up. "-vd" is short for verbose output and detach from containers when done. Specify version if desired, such as '--version 8.12.1'.

elastic-package stack down
	Bring down the stack. Destroys containers.

elastic-package stack up -vd --services package-registry
	Recreates the package-registry container. Use after the build command to make the registry aware of your new package. Beware: If you install the package in Kibana, you can no longer update the package at that version. Increment the package version to make new packages show up. Remember to revert the version back to the original before submitting a PR.

elastic-package test [pipeline|test|static|asset] -v
    Run package tests. Make sure you are in the package's directory. A stack needs to be running for this to work. It is not necessary to build the package for the tests. Pipeline tests are great for rapid iteration given how quickly they run and how comprehensive the validations are. System tests are great for end-to-end tests and validating any changes made to Filebeat (this includes the *.yml.hbs files in data_stream/NAME/agent/stream).

elastic-package test [pipeline|test|static|asset] -v -g
    Regenerate the expected files (pipeline test) or sample_event.json (system system) after the tests run. Ensure that the output is expected before committing changes, as regressions could accidentally become the new expected behavior.
```

## All integrations [_all_integrations]

### Development [_development]

1. When developing integrations and propagating changes to the package registry, first rebuild the package:

    ```bash
    $ cd packages/apache
    $ elastic-package build
    ```

    Then, rebuild and redeploy the Package Registry:

    *It's important to execute the following command in the Integrations repository.*

    ```bash
    $ elastic-package stack up -v -d --services package-registry
    ```

    Explanation: It's much faster to rebuild and restart the container with the Package Registry than to work with mounted volumes.

### Code reviewers [_code_reviewers]

1. Ping "Team:Integrations".

    Use the team label to notify relevant team members about the incoming pull request.

#### Manifest files [_manifest_files_2]

1. Descriptions of configuration options should be as short as possible.

    Include only the meaningful information about the configuration option.

    Good candidates: references to the product configuration, accepted string values, explanation.

    Bad candidates: *Collect metrics from A, B, C, D,…​ X, Y, Z datasets.*

2. Descriptions should be human readable.

    Rephrase sentences like: *Collect foo_Bar3 metrics* to *Collect Foo Bar metrics*.

3. Description should be easy to understand.

    Simplify sentences and don't provide information about the input if not required.

    Bad candidate: *Collect application logs (log input)*

    Good candidates: *Collect application logs*, *Collect standard logs for the application*

4. Letter casing is important for screenshot descriptions.

    These descriptions are visualized in the Kibana UI. Having them clean and consistent creates a better user experience.

    Bad candidate: *filebeat running on ec2 machine*

    Good candidates: *Filebeat running on AWS EC2 machine*

5. If a package relies on a feature or field available only in a specific stack or beats version, `kibana.version` condition should be adjusted accordingly in the package's `manifest.yml`:

    ```yaml
    conditions:
       kibana.version: '^8.7.0'
    ```

    ::::{note}
    The package version with such condition as above will be only available in Kibana version >=8.7.0
    ::::


    ::::{note}
    Changing dashboards and visualizations using an unreleased version of Kibana might be unsafe since the Kibana Team might make changes to the Kibana code and potentially the data models. There is no guarantee that your changes won't be broken by the time new Kibana version is released.
    ::::

#### CI [_ci]

1. Run `elastic-package check` and `elastic-package test` locally.

    To verify if an integration works as intended, execute the same steps as CI:

    ```bash
    $ cd packages/apache
    $ elastic-package check -v
    $ elastic-package test -v
    ```

    Keep in mind that the `elastic-package test` command requires a live cluster running and exported environment variables. The environment variables can be set with `eval "$(elastic-package stack shellinit)"`.

#### Fields [_fields]

1. Remove empty fields files.

    If a fields file (e.g. `package-fields.yml`) doesn't contain any field definitions or it defines root only, it can be removed.

