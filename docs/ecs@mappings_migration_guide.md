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

## Why change?

A new opportunity to improve our handling of ECS mappings appeared when Elasticsearch v8.9.0 [introduced](https://github.com/elastic/elasticsearch/issues/95538) the new [ecs@mappings](https://github.com/elastic/elasticsearch/blob/b4938e16457dc69d392235eaf404a6dad9ddb717/x-pack/plugin/core/template-resources/src/main/resources/ecs%40mappings.json) component template to `logs-*-*` index template. 

With the [ecs@mappings](https://github.com/elastic/elasticsearch/blob/b4938e16457dc69d392235eaf404a6dad9ddb717/x-pack/plugin/core/template-resources/src/main/resources/ecs%40mappings.json) component template, we have an official and maintained definition of ECS mappings template.

However, Fleet v8.9.0 did not include the [ecs@mappings](https://github.com/elastic/elasticsearch/blob/b4938e16457dc69d392235eaf404a6dad9ddb717/x-pack/plugin/core/template-resources/src/main/resources/ecs%40mappings.json) component template in index templates for integrations. 

From stack v8.13.0, Fleet will [include](https://github.com/elastic/kibana/issues/174905) ecs@mappings component templates in all integrations, making it easier for integration users and developers to access logs and metrics data streams.

#### Consequences

- ecs@mappings from Elasticsearch are the single source of truth for ECS mappings.
- ECS mappings are available and out-of-the-box; there is no need to import or reference external mapping.

## How to start using ecs@mappings

### Requirements

Before starting to leverage only the ecs@mappings component template for ECS mappings in your integration package, you need to meet the following requirements:

- The minimum stack version must be 8.13.0.
- The minimum elastic-package version must be 0.99.0.

#### Why elastic-package version 0.99.0+?

When your integration package only supports stack versions 8.13.0+, it validates the field definitions using the fields schema from the ECS repo on sample_event.json and test documents at 

```text
packages/azure/data_stream/activitylogs/_dev/test/pipeline/
```

For example, `elastic-package` fetches the field definitions for ECS 8.11.0 at:

https://raw.githubusercontent.com/elastic/ecs/v8.11.0/generated/ecs/ecs_nested.yml 


### Migration Paths

Here is a list of known migration paths from referencing external fields and importing the legacy ECS mappings.

#### From Referencing ECS fields

You can start by removing references to external definitions and running tests. You should consider a few aspects while migrating from referencing ECS to the ecs@mappings component template.

##### Check your pipeline test coverage

Good coverage in _dev/test/pipeline/ tests is essential for catching problems. Consider adding more sample documents to increase the chances of catching problems.

##### Existing tests may start to fail

For Integrations that target stack 8.13+, elastic-package 0.99 also brings an additional schema validation that can uncover inconsistencies.

For example, by enabling ecs@mappings in Azure Logs, we learned that the current "event.outcome" field value, “succeeded,” is not one of the expected values (it must be between “success”, “failure”, and “unknown”). 

##### Take underlying assumptions into account

The ecs@mappings expect that logs and metrics shippers (and the related pipelines, if any) emit field values using the correct field type.

For example, if you send a document with a boolean field:

```json
{
    "coldstart": true
}
```

Both legacy and modern ECS mappings will map the field as a boolean field type.

However, if your logs source emits something like this document:

```json
{
    "coldstart": "true"
}
```

The modern ecs@mappings will not coerce the value and map this field as a keyword.

We can consider this an edge case. However, it can happen, even if it looks weird. Personally, I had spotted cases like this in one of the major CSPs. I suggest dealing with edge cases from your logs or metrics source using the @custom pipeline or mappings.

Each approach to ECS mappings has its own tradeoffs. If you want to learn more about the one we picked and what other options we considered, you can read https://github.com/elastic/elasticsearch/issues/85146#issuecomment-2031285084 

#### From Importing ECS fields

Integration packages importing legacy ECS mappings do not have field definitions. The transition should be more accessible.

When the min stack version is ^8.13.0, you can stop importing the legacy mappings:

```yaml
# packages/azure_blob_storage/_dev/build/build.yml

dependencies:
  ecs:
    reference: "git@v8.11.0"
    import_mappings: true  # remove this line, default is false.
```

Good `sample_event.json` and test documents are essential. 

### Existing approaches to define mappings will continue to work

In package-spec 3.1.3, we deprecated the use of import_mappings: true. Importing is no longer the recommended way to deal with ECS mappings.

Since the package owners may want to keep the minimum stack version < 8.13, all existing approaches to define mappings will continue to work.

We recommend migrating to ecs@mappings to reap the benefits of centralized and up-to-date ECS field definitions.

#### package-spec recommendations

Consider upgrading to the recent package-spec according to your minimum stack requirements. The benefits (especially additional checks that elastic-package delivers) outweigh the costs.

### Override, if required

The ecs@mappings can deal with ECS mappings in all standard cases. 

However, integration developers can continue using the field definition of specific fields to override the definition in Elasticsearch if needed.


