---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/build-it.html
---

# Build [build-it]

To format, lint, and build your integration, in that order, run:

```bash
elastic-package check
```

Problems and potential solutions will display in the console. Fix them and rerun the command. Alternatively, skip formatting and linting with the `build` command:

```bash
elastic-package build
```

With the package built, run the following command from inside of the integration directory to recycle the package-registry docker container. This refreshes the {{fleet}} UI, allowing it to pick up the new integration in {{kib}}.

```bash
elastic-package stack up --services package-registry
```

