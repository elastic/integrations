---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/build-create-package.html
---

# Create a new package [build-create-package]

Rather than copying the source of an existing package, we recommend using the `elastic-package create` command to build a new package. Running this command ensures that your integration follows the latest recommendations for the package format.

Use the `elastic-package` TUI wizard to bootstrap a new package:

```bash
elastic-package create package
```

The wizard walks you through the creation of the package, including setting a package name, version, category, etc. When the wizard completes, you’ll have a basic package complete with a sample manifest, changelog, documentation, and screenshot.

::::{note}
It may not do anything yet, but your integration can be built and loaded into your locally running package registry from this step forward. Jump to [Build](/extend/build-it.md) at any point in this documentation to take your integration for a test run.

::::
