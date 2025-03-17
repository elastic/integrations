---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/build-spin-stack.html
---

# Spin up the Elastic Stack [build-spin-stack]

The [`elastic-package`](/extend/elastic-package.md) tool provides a quick way to spin up the {{stack}}. The following command deploys {{es}}, {{kib}}, and the {{package-registry}}:

```bash
elastic-package stack up -v -d
```

To view a list of the available options for this command, run:

```bash
elastic-package stack up -h
```

When complete, go to [http://localhost:5601](http://localhost:5601) and log in with the username `elastic` and the password `changeme`.

::::{tip}
Development time over? Tear down the {{stack}} with:

```bash
elastic-package stack down
```

::::


