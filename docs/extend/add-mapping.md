---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/add-a-mapping.html
---

# Edit field mappings [add-a-mapping]

When you build an integration, you need to tell {{es}} how to store and index each field in your data. This is called mapping. Mappings define the data type (like keyword, date, or integer) and other properties for every field your integration creates.


::::{admonition}
**Mapping** is how you describe the structure of your data to {{es}}. Each field in your documents needs a mapping so {{es}} knows how to store, search, and analyze it. Each document is a collection of fields, each having its own data type. When mapping your data, you create a mapping definition listing all relevant fields and their types. A mapping definition can also include metadata fields, like the `_source` field, which control how document metadata is handled.

To learn more, see [mapping](docs-content://manage-data/data-store/mapping.md).

::::

## Where do mappings live in an integration [where-do-mappings-live]

Each data stream in your integration has a `fields` directory. This directory contains YAML files that describe all the fields for that data stream. When you build your integration, these files are combined to create the mapping for the data stream.

Like ingest pipelines, mappings only apply to the data stream dataset, for our example the `apache.access` dataset.

Example structure:

```text
apache
└───data_stream
    ├── access
    │   └── fields
    │       ├── agent.yml
    │       ├── base-fields.yml
    │       ├── ecs.yml
    │       └── fields.yml
    ├── error
    │   └── fields
    │       ├── agent.yml
    │       ├── base-fields.yml
    │       ├── ecs.yml
    │       └── fields.yml
    └── status
```

:::{note}
You can name these files however you like, as long as they end with `.yml`.
:::

## How to define field mappings [how-to-define-mappings]

### 1. Use ECS (Elastic Common Schema) fields when possible [use-ecs]

ECS is a shared schema for common fields (like `host.name`, `event.dataset`, etc.).

* If your integration only supports Elastic Stack 8.13.0 and above:
You can rely on the [ecs@mappings](https://github.com/elastic/elasticsearch/blob/c2a3ec42632b0339387121efdef13f52c6c66848/x-pack/plugin/core/template-resources/src/main/resources/ecs%40mappings.json) component template installed by {{fleet}}. This makes explicitly declaring ECS fields unnecessary; the `ecs@mappings` component template in {{es}} will automatically detect and configure them. However, should ECS fields be explicitly defined, they will overwrite the dynamic mapping provided by the `ecs@mappings` component template.

* If your integration supports older versions (<8.13.0):
You can import ECS mappings dynamically by setting `import_mappings: true` in the ECS section of the `_dev/build/build.yml` file in the root of the package directory. This introduces a [dynamic mapping](https://github.com/elastic/elastic-package/blob/f439b96a74c27c5adfc3e7810ad584204bfaf85d/internal/builder/_static/ecs_mappings.yaml) with most of the ECS definitions. Using this method means that, just like the previous approach, ECS fields don’t need to be defined in your integration, they are dynamically integrated into the package at build time. Explicitly defined ECS fields can be used and will also overwrite this mechanism.

    An example of the aformentioned `build.yml` file for this method:

    ```yaml
    dependencies:
      ecs:
        reference: git@v8.6.0
        import_mappings: true
    ```

* Explicitly define or import individual ECS fields:
You can always explicitly define ECS fields, which will override dynamic mappings.
This can be done in two ways: 
  - Use `external: ecs` to reference a field from ECS.
  - Or, define the field directly in your YAML.

  #### How does `external: ecs` work? [how-ecs-works]
  
  * When you define a field in your integration’s mapping YAML with `external: ecs`, you’re telling the `elastic-package` tool *not* to define the field’s mapping details directly in your package. Instead, you want to import the field definition from the official ECS.

  * The `elastic-package` CLI will look up the field’s definition in an external ECS reference file, rather than requiring you to copy the full field definition into your package.

  * By default it looks at the [ECS reference](https://raw.githubusercontent.com/elastic/ecs/v8.6.0/generated/ecs/ecs_nested.yml) file hosted on Github. 

  * The exact version (or location) of the ECS reference file is controlled by the reference setting in your package’s `_dev/build/build.yml file`. For example:

    ```yaml
    dependencies:
      ecs:
        reference: git@v8.6.0
    ```

    This tells `elastic-package` to use ECS version 8.6.0.

    Example explicit field definition:

    ```yaml
    - name: cloud.acount.id
      level: extended
      type: keyword
      ignore_above: 1024
      description: 'The cloud account or organ....'
      example: 43434343
    ```



* Local ECS reference file (air-gapped setup):
In some environments—such as secure, air-gapped, or offline setups—you may not have internet access to fetch the ECS field definitions directly from GitHub. In these cases, you can download the ECS reference file manually and tell the elastic-package tool to use this local file instead of the remote one.

  
    * First, download the [ECS YAML file](https://raw.githubusercontent.com/elastic/ecs/v8.6.0/generated/ecs/ecs_nested.yml) to a location on your local machine or network.

    * In your integration’s `_dev/build/build.yml` file, set the reference to the full file path of your downloaded ECS reference. For example:

    ```yaml
    dependencies:
      ecs:
        reference: file:///home/user/integrations/packages/apache/ecs_nested.yml
    ```
    (Make sure to use the correct absolute path for your environment.)

    * Now, when you use external: ecs in your field mappings, the `elastic-package` CLI will look up field definitions in your local ECS file, not on GitHub.


### 2. Define custom fields [define-custom-fields]

If your integration needs fields that aren’t in ECS, define them in `fields.yml`:

The example below defines field `apache.access.ssl.protocol` in the Apache integration.

```yaml
- name: apache.access
  type: group
  fields:
    - name: ssl.protocol
      type: keyword
      description: |
        SSL protocol version.
```

### 3. Understand the common field files [understand-common-field-files]

#### agent.yml [_agent_yml]

The `agent.yml` file defines fields used by default processors. Examples: `cloud.account.id`, `container.id`, `input.type`

#### base-fields.yml [_base_fields_yml]

In this file, the `data_stream` subfields `type`, `dataset` and `namespace` are defined as type `constant_keyword`, the values for these fields are added by the integration. The `event.module` and `event.dataset` fields are defined with a fixed value specific for this integration: - `event.module: apache` - `event.dataset: apache.access` Field `@timestamp` is defined here as type `date`.

#### ecs.yml [_ecs_yml]:

Contains ECS fields, either imported or explicitly defined.

#### fields.yml [_fields_yml]

Custom fields unique to your integration.

Learn more about fields in the [general guidelines](/extend/general-guidelines.md#_document_all_fields).

:::{tips}
* Start with ECS fields: Use ECS wherever possible for compatibility and consistency.
* Be descriptive: Add clear descriptions to each field to help users and maintainers.
* Keep fields unique: Each field name should be unique within a data stream.
* Test your mappings: Use `elastic-package check` to validate your mappings before submitting.
:::