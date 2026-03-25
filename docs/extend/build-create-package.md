---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/build-create-package.html
---

# Create a new package [build-create-package]

Rather than copying the source of an existing package, we recommend using the [`elastic-package create`](https://github.com/elastic/elastic-package/blob/main/docs/howto/create_new_package.md) command to build a new package. Running this command ensures that your integration follows the latest recommendations for the package format.

Use the `elastic-package` TUI wizard to bootstrap a new package:

```bash
elastic-package create package
```

The wizard guides you through all required configuration:

* **Package type:** Choose between `integration`, `input`, or `content` package types
* **Package metadata:** Name, title, version, and description
* **License:** Select from Elastic 2.0, Apache 2.0, or add a license later
* **Categories:** Multi-select from available categories (aws, azure, cloud, security, etc.)
* **Kibana version:** Specify the minimum Kibana version constraint
* **Elastic subscription:** Required subscription level (basic, gold, platinum, enterprise)
* **Owner information:** GitHub owner and owner type (elastic, partner, community)

When the wizard completes, you'll have a working package with:

* A complete `manifest.yml` with all required metadata
* A `changelog.yml` with an initial entry
* A README template in `_dev/build/docs/README.md` following the [documentation guidelines](documentation-guidelines.md)
* [Documentation structure validation](finishing-touches.md#documentation-structure-validation) enabled in `validation.yml`
* Sample icon and screenshot images

Navigate into your new package directory:

```bash
cd <your-package-name>
```

You should see a structure similar to:

```bash
<your-package-name>/
├── manifest.yml
├── data_stream/
├── docs/
└── img/
```

* `manifest.yml`: Main metadata file for your package.
* `data_stream/`: Where you'll add data streams (see below).
* `docs/`: Documentation for your integration (generated from templates).
* `img/`: Images including icons and screenshots.
* `_dev/build/docs/`: README template with placeholder content.
* `validation.yml`: Package validation configuration.

## Add data streams

Use `elastic-package create data-stream` to add data streams to your package:

```bash
elastic-package create data-stream
```

The wizard prompts you for:

* **Data stream name and title**
* **Type:** `logs` or `metrics`
* **For logs:** Select from available input types (filestream, cel, aws-s3, aws-cloudwatch, azure-blob-storage, tcp, udp, http_endpoint, and more)
* **For metrics:** Configure time series mode and synthetic source settings for optimized storage

Each data stream is created with a manifest, sample fields, and an ingest pipeline that you can customize.

## Customize the package

Manually update and extend the package to meet your integration's requirements:

- Define policy templates and data stream inputs
- Add custom icons and screenshots
- Complete the README.md file
- Update the changelog.yml with accurate version history and descriptions


::::{note}
It may not do anything yet, but your integration can be built and loaded into your locally running package registry from this step forward. Jump to [Build](/extend/build-it.md) at any point in this documentation to take your integration for a test run.

::::


