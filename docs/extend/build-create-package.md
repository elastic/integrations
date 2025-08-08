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

The wizard will prompt you to enter several fields (e.g., description, categories, type).

When the wizard completes, you’ll have a basic package complete with a sample manifest, changelog, documentation, and screenshot.

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

manifest.yml: Main metadata file for your package.
data_stream/: Where you’ll add data streams (use elastic-package create data-stream).
docs/: Documentation for your integration.
img/: Images for documentation.


Manually update and extend the package to meet your integration's requirements:

- Define policy templates and data stream inputs
- Add custom icons and screenshots
- Complete the README.md file
- Update the changelog.yml with accurate version history and descriptions


::::{note}
It may not do anything yet, but your integration can be built and loaded into your locally running package registry from this step forward. Jump to [Build](/extend/build-it.md) at any point in this documentation to take your integration for a test run.

::::


