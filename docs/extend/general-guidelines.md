---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/general-guidelines.html
---

# General guidelines [general-guidelines]

::::{important}
The following guidelines capture general aspects of the integrations that can be improved and should not be treated as a mandatory list of requirements every package should adhere to. Some guidelines that are applicable to one integration can be completely irrelevant to another. Treat them as best effort.
::::


While the guidelines focus on metrics, they are equally applicable to logs.


## Data types [_data_types]

Given that all packages are basic, developers should use Basic types (for example `histogram`. `wildcard`, etc.) when applicable. Of course, for ECS (see below) we should use the type specified by ECS.


## ECS compliance [_ecs_compliance]

An integration package should be compliant with the most recent version of ECS. This implies an increased amount of relevant ECS fields populated by an integration.

Starting with ECS 1.6, ECS is going to start using Basic types for some fields. Integration fields should be upgraded to the new types as part of the process.


## Document all fields [_document_all_fields]

All fields produced by an integration must be mapped by `fields.yml`. This guarantees that their index mapping is correct, and Kibana has enough information to deal with all fields.


### Field limits [_field_limits]

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

::::{note}
For backwards compatibility, the limit is automatically bumped to 10000 fields if there are more than 500 fields explicitly defined for a data stream, however newly created integrations should not rely on this behavior but instead assume a fixed limit of 1000 fields.
::::



### Specify metric types and units [_specify_metric_types_and_units]

As part of the field definition, there are two settings that add metadata which will help Kibana graphing it:

* `unit` applies to all data types, defines the units of the field. Examples of units are `byte` and `ms`. When using `percent` for percentages, the convention is to use 1 for 100%. You can find the full list of supported units in the [package spec](https://github.com/elastic/package-spec/blob/ff8286d0c40ad76bb082e9c8ea78f4551c2519c1/spec/integration/data_stream/fields/fields.spec.yml#L103).
* `metric_type` applies to metric events only, to be added to metric fields. It defines their metric type. It can be of type `gauge` or `counter`. Counters are used for metrics that always increase over time, such as number of page visits. Gauges are used for amounts that can increase or decrease over time, such as the amount of memory being used.

The Elasticsearch documentation details the [expected values for these two fields](elasticsearch://reference/elasticsearch/mapping-reference/mapping-field-meta.md).

Other applications, including Kibana, can use the information provided by this metadata when accessing these fields. The `unit` is used when formatting the values of the field, and the `metric_type` can be used to provide better defaults when quering the data.


### Specify dimensions [_specify_dimensions]

A set of fields of a data stream can be defined as dimensions. A set of dimensions with the same values identify a single time series.

It is important to choose the set of fields carefully. They should be the minimal set of dimensions required to properly identify any time series included in the data stream. Too few dimensions can mix data of multiple time series into a single one, while too many dimensions can impact performance.

A field can be configured as a dimension by setting `dimension: true` in its definition.

Only fields of certain data types can be defined as dimensions. These data types include keywords, IPs and numeric types.

Some guidelines to take into account when chosing dimensions:

* They can affect ingestion performance, it is recommended to have as few dimensions as possible. When selecting dimensions, try to avoid redundant ones, such as unique identifiers and names that refer to the same object.
* Also be careful with having too few dimensions. There can be only one document with the same timestamp for a given set of dimensions. This can lead to data loss if different objects produce the same dimensions.
* Changing dimensions can be a breaking change. A different set of dimensions produces a different time series, even if they select the same data.

Declaring dimensions is a requisite to use TSDB indexes. These indexes are optimized for time series use cases, bringing disk storage savings and additional queries and aggregations.

TSDB indexes can be enabled in data streams by setting `elasticsearch.index_mode: time_series` in their manifests.


## Logs and Metrics UI compatibility [_logs_and_metrics_ui_compatibility]

When applicable an integrataion package should provide the relevant fields for the Logs and Metrics Apps. This is especially relevant for integrations that are focused on compute-resources (VMs, containers, etc.).

* Keep the [Logs app fields](docs-content://reference/observability/fields-and-object-schemas/logs-app-fields.md) reference up to date.
* Keep the [Infrastructure app fields](docs-content://reference/observability/fields-and-object-schemas/metrics-app-fields.md) reference up to date.


## Subtracting metrics [_subtracting_metrics]

An integration package should collect a reasonable amount of metrics for any target system. In some cases this may mean removing some metrics that Filebeat and Metricbeat are collecting today. Collecting too many metrics has implications on metric storage as well as relevance of the data provided to the user.

Potential candidates to remove:

* low-level garbage collector metrics
* internal metrics showing code flow (for example, `Got100Continue`, `Wait100Continue`)
* redundant metrics (for example, metric collection for MQ topics doesn’t require collection of summary metrics)


## Relevant metrics [_relevant_metrics]

This is probably the most important and hardest one of the guidelinesto satisfy, as it requires knowledge of every target system. Identifying relevant metrics should be considered case by case.

There are no well defined guidelines for this exercise. It can be as simple as finding everything in one place (for example the [RabbitMQ documentation](https://www.rabbitmq.com/monitoring.html)) or as difficult as reviewing multiple sources including documentation, blog posts, and other integrations, and consolidating the discovered information in one place for revision. A recommendation is to only collect the metrics that are needed for dashboards and visualizations in general.


## Keep the original message field [_keep_the_original_message_field]

Log integrations should keep the original message field (recommended name: `event.original`) so that it shows up in the Logs UI. It will also be useful when users want to reindex the data after changing a pipeline. In addition, the message field can be used as source for the some future Runtime fields.

The original field should be user-configurable with the Kibana UI for better cost and storage management, and also consistency with other integrations.


## Document storage efficiency [_document_storage_efficiency]

Every integration should strive to store collected data as efficiently as possible, which implies optimizing the way each integration generates documents.


## Default datasets [_default_datasets]

When applicable, an integration package should provide a default dataset that aggregates a subset of the most relevant metrics across other data streams. Think of these as the metrics that are visualized on overview dashboards or are used for alerting. A guideline for creating a separate default dataset could be when the number of datasets in a package is more than three.


## Updated versions [_updated_versions]

An integration package should support the most relevant versions of a target system. Some of our integrations support older versions of a target service/system, which were relevant at the time of implementation. Over time they can become outdated and require a revision, which can be as simple as testing the integration against the latest version and updating the compatibility section in the documentation, or it can mean refactoring the code to work with the latest version. For example, the Ceph module has recently been updated to support the latest version which had an entirely different way of collecting metrics. In order to accommodate both older and new versions in the module, metricsets were created in the module specifically for newer versions and it was noted in the documentation which metricsets to use.


## Updated configuration defaults [_updated_configuration_defaults]

An integration package should provide meaningful defaults, such as collection intervals (periods), enabled metricsets, and any other integration specific configuration parameters. In the majority of cases users opt to use defaults. Hence, providing the relevant default values is crucial for the integration to be useful. In addition, integrations should strive to provide a one-click experience by providing the defaults that can cover 80% of use cases.


## Updated docs [_updated_docs]

Integration packages should provide consistent and comprehensive documentation. For more details, refer to the [documentation guidelines](/extend/documentation-guidelines.md).


## Updated integration content [_updated_integration_content]

Integration packages should provide out-of-the-box dashboards. For more details, refer to the [dashboard guidelines](/extend/dashboard-guidelines.md).


## Content for elastic.co/integrations [_content_for_elastic_cointegrations]

Each integration will be listed on the public website `elastic.co/integrations` and the package registry will serve as the source of truth. As a result, documentation and screenshots should be high quality to showcase the integration. Please ensure to use `svg` for the logo and `png` for all other images. Any additional branding material should be reviewed carefully, for example:

* logo format and quality
* permission to use logos and trademarks


## Curated user experiences [_curated_user_experiences]

It’s advised to set integration policies in Fleet. Every integration and agent should be visible in Fleet and users should be able to add the integration directly from the integration list. This leads to better cohesion since it provides a consistent experience across integrations, allow users to add several integrations at once, and avoids sending them back and forth between multiple apps. It also allows users to discover new integrations in the list.

Elastic products will also have the option to provide a curated UI for settings that are difficult to put in Fleet. It’s up to the product to decide how much flexibility they want to provide in changing the configuration directly from Fleet. This will depend on the use case and if it makes sense. Some level of configuration is recommended though.


## Asset tagging and metadata [_asset_tagging_and_metadata]

When assets are installed through Fleet some metadata is added by default.

For Elasticsearch assets such as index templates and ingest pipelines, a `_meta` property is added to the asset as follows:

```json
{
  "managed_by": "fleet",
  "managed": true,
  "package": {
    "name": "<package name>"
  }
}
```

For Kibana assets, [tags](docs-content://explore-analyze/find-and-organize/tags.md) are generated in addition to the `_meta` property:

* One tag with a `name` matching the package’s `title` property
* The `managed` tag, which Kibana uses to recognize "system" assets, or those that are installed by Kibana itself instead of generated by an end user

