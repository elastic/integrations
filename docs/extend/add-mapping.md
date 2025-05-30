---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/add-a-mapping.html
---

# Edit field mappings [add-a-mapping]

Ingest pipelines create fields in an {{es}} index, but don’t define the fields themselves. Instead, each field requires a defined data type or mapping.

::::{admonition}
**Mapping** is the process of defining how a document, and the fields it contains, are stored and indexed. Each document is a collection of fields, each having its own data type. When mapping your data, create a mapping definition containing a list of fields pertinent to the document. A mapping definition also includes metadata fields, like the _source field, which customize how the associated metadata of a document is handled.

To learn more, see [mapping](docs-content://manage-data/data-store/mapping.md).

::::


In the integration, the `fields` directory serves as the blueprint used to create component templates for the integration. The content from all files in this directory will be unified when the integration is built, so the mappings need to be unique per data stream dataset.

Like ingest pipelines, mappings only apply to the data stream dataset, for our example the `apache.access` dataset.

:::{note}
The names of these files are conventions, any file name with a `.yml` extension will work.
:::

Integrations have had significant enhancements in how ECS fields are defined. Below is a guide on which approach to use, based on the version of Elastic your integration will support.

1. ECS mappings component template (>=8.13.0) Integrations **only** supporting version 8.13.0 and up, can use the [ecs@mappings](https://github.com/elastic/elasticsearch/blob/c2a3ec42632b0339387121efdef13f52c6c66848/x-pack/plugin/core/template-resources/src/main/resources/ecs%40mappings.json) component template installed by Fleet. This makes explicitly declaring ECS fields unnecessary; the `ecs@mappings` component template in Elasticsearch will automatically detect and configure them. However, should ECS fields be explicitly defined, they will overwrite the dynamic mapping provided by the `ecs@mappings` component template. They can also be imported with an `external` declaration, as seen in the example below.

1. Dynamic mappings imports (<8.13.0 & >=8.13.0) Integrations supporting the Elastic stack below version 8.13.0 can still dynamically import ECS field mappings by defining `import_mappings: true` in the ECS section of the `_dev/build/build.yml` file in the root of the package directory. This introduces a [dynamic mapping](https://github.com/elastic/elastic-package/blob/f439b96a74c27c5adfc3e7810ad584204bfaf85d/internal/builder/_static/ecs_mappings.yaml) with most of the ECS definitions. Using this method means that, just like the previous approach, ECS fields don’t need to be defined in your integration, they are dynamically integrated into the package at build time. Explicitly defined ECS fields can be used and will also overwrite this mechanism.

    An example of the aformentioned `build.yml` file for this method:

    ```yaml
    dependencies:
      ecs:
        reference: git@v8.6.0
        import_mappings: true
    ```

1. Explicit ECS mappings As mentioned in the previous two approaches, ECS mappings can still be set explicitly and will overwrite the dynamic mappings. This can be done in two ways: - Using an `external: ecs` reference to import the definition of a specific field. - Literally defining the ECS field.

    The `external: ecs` definition instructs the `elastic-package` command line tool to refer to an external ECS reference to resolve specific fields. By default it looks at the [ECS reference](https://raw.githubusercontent.com/elastic/ecs/v8.6.0/generated/ecs/ecs_nested.yml) file hosted on Github. This external reference file is determined by a Git reference found in the `_dev/build/build.yml` file, in the root of the package directory. The `build.yml` file set up for external references:

    ```yaml
    dependencies:
      ecs:
        reference: git@v8.6.0
    ```

    Literal definition a ECS field:

    ```yaml
    - name: cloud.acount.id
      level: extended
      type: keyword
      ignore_above: 1024
      description: 'The cloud account or organ....'
      example: 43434343
    ```

1. Local ECS reference file (air-gapped setup) By changing the Git reference in in `_dev/build/build.yml` to the path of the downloaded [ECS reference](https://raw.githubusercontent.com/elastic/ecs/v8.6.0/generated/ecs/ecs_nested.yml) file, it is possible for the `elastic-package` command line tool to look for this file locally. Note that the path should be the full path to the reference file. Doing this, our `build.yml` file looks like:

    ```
    dependencies:
      ecs:
        reference: file:///home/user/integrations/packages/apache/ecs_nested.yml
    ```


The `access` data stream dataset of the Apache integration has four different field definitions:

:::{note}
The `apache` integration below has not yet been updated to use the dynamic ECS field definition and uses `external` references to define ECS fields in `ecs.yml`.
:::

```text
apache
└───data_stream
│   └───access
│   │   └───elasticsearch/ingest_pipeline
│   │   │      default.yml
│   │   └───fields
│   │          agent.yml
│   │          base-fields.yml
│   │          ecs.yml
│   │          fields.yml
│   └───error
│   │   └───elasticsearch/ingest_pipeline
│   │   │      default.yml
│   │   └───fields
│   │          agent.yml
│   │          base-fields.yml
│   │          ecs.yml
│   │          fields.yml
│   └───status
```

## agent.yml [_agent_yml]

The `agent.yml` file defines fields used by default processors. Examples: `cloud.account.id`, `container.id`, `input.type`


## base-fields.yml [_base_fields_yml]

In this file, the `data_stream` subfields `type`, `dataset` and `namespace` are defined as type `constant_keyword`, the values for these fields are added by the integration. The `event.module` and `event.dataset` fields are defined with a fixed value specific for this integration: - `event.module: apache` - `event.dataset: apache.access` Field `@timestamp` is defined here as type `date`.


## fields.yml [_fields_yml]

Here we define fields that we need in our integration and are not found in the ECS. The example below defines field `apache.access.ssl.protocol` in the Apache integration.

```yaml
- name: apache.access
  type: group
  fields:
    - name: ssl.protocol
      type: keyword
      description: |
        SSL protocol version.
```

Learn more about fields in the [general guidelines](/extend/general-guidelines.md#_document_all_fields).
