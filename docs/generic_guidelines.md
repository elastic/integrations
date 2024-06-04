# Integrations Development Guidelines

_DISCLAIMER_: The following guidelines capture general aspects of the integrations that can be improved and should not be treated as a mandatory list of requirements every package should adhere to. Some guidelines that are applicable to one integration can be completely irrelevant to another. Treat them as best effort.

While the guidelines focus on metrics, they are equally applicable to logs.

#### Data types

Given that all packages are basic, developers should use Basic types (e.g. `histogram`. `wildcard`, etc.) when applicable. Of course, for ECS (see below) we should use the type specified by ECS.

#### ECS compliance

An integration package should be compliant with the most recent version of ECS. This implies an increased amount of relevant ECS fields populated by an integration.

Starting with ECS 1.6, ECS is going to start using Basic types for some fields. Integration fields should be upgraded to the new types as part of the process.

#### Document all fields

All fields produced by an integration must be mapped by `fields.yml`. This guarantees that their index mapping is correct, and Kibana has enough info to deal with all fields.

##### Field limits

By default, data streams will have a `total_fields.limit` setting of 1000. Besides defined custom fields, this also includes dynamically generated ECS fields. If your data stream is expected to eventually house more than 1000 fields, set an explicit limit in the `manifest.yml` of the data stream:
```yaml
elasticsearch:
  index_template:
    settings:
      index:
        mapping:
          total_fields:
            limit: 5000
```

Note: For backwards compatibility, the limit is automatically bumped to 10000 fields if there are more than 500 fields explicitly defined for a data stream, however newly created integrations should not rely on this behavior but instead assume a fixed limit of 1000 fields.

##### Specify metric types and units

As part of the field definition, there are two settings that add metadata which will help Kibana graphing it:

- `unit` applies to all data types, defines the units of the field. Some
  examples of units are `byte` or `ms`. When using `percent` for percentages,
  the convention is to use 1 for 100%. You can find the full list of supported
  units in the [package spec](https://github.com/elastic/package-spec/blob/ff8286d0c40ad76bb082e9c8ea78f4551c2519c1/spec/integration/data_stream/fields/fields.spec.yml#L103).
- `metric_type` applies to metric events only, to be added to metric fields,
  it defines their metric type. It can be of type `gauge` or `counter`. Counters
  are used for metrics that always increase over time, as number of visits.
  Gauges are used for amounts that can increase or decrease over time, as the
  memory used.

Elasticsearch docs details the [expected values for these two fields](https://www.elastic.co/guide/en/elasticsearch/reference/master/mapping-field-meta.html).

Other applications, like Kibana, can use the information provided by this
metadata when accessing these fields. The `unit` is used when formatting the
values of the field, and the `metric_type` can be used to provide better defaults
when quering the data.

##### Specify dimensions

A set of fields of a data stream can be defined as dimensions. A set of dimensions
with the same values identify a single time serie.

It is important to choose wisely the set of fields, they should be the minimal set
of dimensions required to properly identify any time serie included in the data stream.
Too few dimensions can mix data of multiple time series into a single one, too many can
impact performance.

A field can be configured as a dimension by setting `dimension: true` on its
definition.

Only fields of certain data types can be defined as dimensions. These data types
include keywords, IPs and numeric types.

Some guidelines to take into account when chosing dimensions:
- They can affect ingestion performance, it is recommended to have as few dimensions as
  possible. When selecting dimensions, try to avoid redundant ones, as unique
  identifiers and names that refer to the same object.
- Be also careful with having too few dimensions. There can be only one document
  with the same timestamp for a given set of dimensions. This can lead to data
  loss if different objects produce the same dimensions.
- Changing dimensions can be a breaking change. A different set of dimensions
  produces a different time serie, even if they select the same data.

Declaring dimensions is a requisite to use TSDB indexes. These indexes are
optimized for time series use cases, bringing disk storage savings and additional
queries and aggregations.

TSDB indexes can be enabled in data streams by setting `elasticsearch.index_mode: time_series`
in their manifests.

#### Logs and Metrics UI compatibility

When applicable an integrataion package should provide the relevant fields for the Logs and Metrics Apps. This is especially relevant for integrations that are focused on compute-resources (VMs, containers, etc.). 

- Keep the [Logs UI fields reference](https://www.elastic.co/guide/en/logs/guide/current/logs-fields-reference.html) up to date.
- Keep the [Metrics UI fields reference](https://www.elastic.co/guide/en/metrics/guide/current/metrics-fields-reference.html) up to date.

#### Subtracting metrics

An integration package should collect a reasonable amount of metrics for any target system. In some cases it may mean removing some metrics that Filebeat and Metricbeat are collecting today. Collecting too many metrics has implications on metric storage as well as relevance of the data provided to the user.

Potential candidates to remove:
- low-level garbage collector metrics
- internal metrics showing code flow (e.g. `Got100Continue`, `Wait100Continue`)
- redundant metrics (e.g. metric collection for MQ topics doesn't require to collect summary metrics)

#### Relevant metrics

Probably the most important and in fact the hardest one of them all as it requires knowledge of every target system. Identifying relevant metrics should be considered case by case.

There are no well defined guidelines for this exercise, as it can be as simple as finding everything in one place (like the [RabbitMQ’s documentation](https://www.rabbitmq.com/monitoring.html)) or as hard as going through multiple sources like docs, blog posts, competitors’ integrations and consolidating the discovered information in one place for revision. A good indicator is to only collect the metrics that are needed for dashboards/visualizations in general.

#### Keep the original message field

Log integrations should keep the original message field (recommended name: `event.original`) so it shows up in the Logs UI. It will also be useful when users want to reindex the data after changing a pipeline. In addition, the message field can be used as source for the some future Runtime fields.

The original field should be user-configurable with the Kibana UI for better cost and storage management, and also consistency with other integrations.

#### Document storage efficiency

Every integration should strive to store collected data as efficiently as possible, which implies optimizing the way each integration generates documents. 

<!---
TODO: this section would benefit from a separate document describing best practices for storing metrics in Elasticsearch efficiently).
-->

#### Default datasets

When applicable an integration package should provide a default dataset that aggregates a subset of most relevant metrics across other data streams. Think of them as the metrics that are visualized on overview dashboards or use for alerting. A rule of thumb for creating a separate default dataset could be when the number of datasets in a package is more than 3.

#### Updated versions

An integration package should support the most relevant versions of a target system. Some of our integrations support older versions of a target service/system, which were relevant at the time of implementation. Over time they get outdated and require a revision, which can be as simple as testing the integration against the latest version and updating the compatibility section in the docs, or it can mean refactoring the code to work with the latest version.
_For example, the Ceph module has recently been updated to support the latest version which had an entirely different way of collecting metrics. In order to accommodate both older and new versions in the module, there were created metricsets in the module specifically for newer versions and noted in the docs which metricsets to use._

#### Updated configuration defaults

An integration package should provide meaningful defaults, such as collection intervals (periods), enabled metricsets and any other integration specific configuration parameters.
In the majority of cases users stick to defaults, because they don’t really know what they need and they trust us to make the call. Hence providing the relevant default values is crucial for the integration to be useful. In addition integrations should strive to provide one-click experience by providing the defaults that can cover 80% of use cases.

#### Updated docs

Integration packages should provide consistent and comprehensive documentation.
For more details, see the [Documentation guidelines](./documentation_guidelines.md).

#### Updated integration content

Integration packages should provide out-of-the-box dashboards.
For more details, see the [Dashboard guidelines](./dashboard_guidelines.md).

#### Content for elastic.co/integrations

Each integration will be listed on the public website elastic.co/integrations and the package registry will serve as the source of truth. As a result, our docs and screenshots should be high quality to showcase the integration. Please ensure to use `svg` for the logo and `png` for all other images. Any additional branding material should be reviewed, e.g.:

- logo format and quality
- permission to use logos and trademarks

#### Curated user experiences

It's advised to set integration policies in the Fleet. Every integration and agent should be visible in Fleet and users should be able to add the integration directly from the integration list. This will lead to better cohesion since it will provide a consistent experience across integrations, allow users to add several integrations at once, and avoid sending them back and forth between multiple apps. It will also allow users to discover new integrations in the list.

Elastic products will also have the option to provide a curated UI for settings that are difficult to put in Fleet. It's up to the product to decide how much flexibility they want to provide in changing the configuration directly from Fleet. This will depend on the use case and if it makes sense. Some level of configuration is recommended though.

#### Asset tagging and metadata

When assets are installed through Fleet, some metadata will be added by default. 

For Elasticsearch assets like Index Templates and Ingest Pipelines, a `_meta` property will be added to the asset as follows

```json
{
  "managed_by": "fleet",
  "managed": true,
  "package": {
    "name": "<package name>"
  }
}
```

For Kibana assets, [tags](https://www.elastic.co/guide/en/kibana/current/managing-tags.html) will be generated in addition to the `_meta` property:
- One tag with a `name` matching the package's `title` property
- The `Managed` tag, which Kibana uses to recognize "system" assets, or those that are installed by Kibana itself instead of generated by an end user
