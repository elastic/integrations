---
description: Enable automatic installation for your content package if data with a matching dataset is ingested in Elasticsearch.
---

# Enable automatic installation for content packages [auto-install-content-packages]

As of version 9.2.0, {{kib}} can automatically install content packages when it detects matching data in {{es}}. This feature uses the `data_stream.dataset` attribute to identify relevant content and install assets such as dashboards and alerts without requiring user intervention.

When data is ingested with a specific `data_stream.dataset` value, {{kib}} checks the {{package-registry}} for content packages that have at least one matching dataset defined in their `discovery.datasets` field. If there is a matching content package, {{kib}} automatically installs it.

## Requirements [auto-install-content-packages-requirements]

- {{kib}} version 9.2.0 or later
- The `format_version` in the content package's `manifest.yml` must specify `3.4.1` or later.

## Configuration [auto-install-content-packages-configuration]

To enable automatic installation for your content package, add the `discovery.datasets` property to your package's `manifest.yml` file. This property should be defined as an array of objects, each with a `name` field specifying a dataset. For example:

```yml
# my_content_package/manifest.yml

format_version: 3.4.1
name: my_content_package
version: 1.0.0
type: content

# ...

discovery:
  fields: []
  datasets:
    - name: my.dataset
    - name: other.dataset
```

If you publish a content package with this configuration, {{kib}} will automatically install the package when data with `data_stream.dataset: "my.dataset"` or `data_stream.dataset: "other.dataset"` is ingested in {{es}}.