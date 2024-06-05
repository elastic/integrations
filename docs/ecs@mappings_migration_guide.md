# ecs@mappings migration guide for integration developers

## History

In the initial stages, our approach involved individually specifying ECS fields within each package.

```yaml
- name: provider
  level: extended
  type: keyword
  ignore_above: 1024
  description: Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean.
```

As we progressed, the need for more efficient methodologies became apparent, prompting us to explore alternative strategies.

**How are integrations handling ECS mappings today?**

Today, integrations employ one of two strategies to manage ECS mappings:

- Referencing ECS mappings (the predominant method)
- Importing ECS mappings (a smaller subset, approximately 40 integrations, opt to import ECS mappings directly)

### Referencing ECS fields

Define external dependency:

```yaml
# packages/azure/_dev/build/build.yml

dependencies:
  ecs:
    reference: git@v8.11.0
```

Developers can reference the external definition:

```yaml
# packages/azure/data_stream/activitylogs/fields/agent.yml

- name: cloud.provider
  external: ecs
```

#### Consequences

Even if each field references the external definition, integration developers must list all fields in various `.yml` files.

### Importing ECS mappings

In early 2023, we [added](https://github.com/elastic/elastic-package/pull/1073) the option of importing the ECS mappings during the package build to avoid explicitly listing all the fields.

When we set `import_mappings: true` in the `_dev/build/build.yml` file, elastic-package fetches the static [ecs_mappings.yml](https://github.com/elastic/elastic-package/blob/a44250eda089f89cc820c0ba5492bef71857aeb1/internal/builder/_static/ecs_mappings.yaml) file and embeds its content in the `logs-azure.eventhub@package` component template.

```yaml
# packages/azure_blob_storage/_dev/build/build.yml

dependencies:
  ecs:
    reference: "git@v8.11.0"
    import_mappings: true
```

With `import_mappings: true`, the package doesn’t need to define ECS fields.

```yaml
# packages/azure_blob_storage/data_stream/generic/iamnotneeded.yml

¯\_(ツ)_/¯
```

See [Custom Azure Blob Storage Input](https://github.com/elastic/integrations/tree/main/packages/azure_blob_storage) as an example of integrations importing ECS mappings.

#### Consequences

- There is no need to define ECS fields \o/
- ECS field definitions come from one place, the static [ecs_mappings.yml](https://github.com/elastic/elastic-package/blob/a44250eda089f89cc820c0ba5492bef71857aeb1/internal/builder/_static/ecs_mappings.yaml) file in elastic-package sources.
- However, setting up elastic-package has a maintenance cost of keeping [ecs_mappings.yml](https://github.com/elastic/elastic-package/blob/a44250eda089f89cc820c0ba5492bef71857aeb1/internal/builder/_static/ecs_mappings.yaml) up-to-date with changes in ECS.

