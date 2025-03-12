---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/static-testing.html
---

# Static testing [static-testing]

Static tests allow you to verify if all static resources of the package are valid, e.g. are all fields of the `sample_event.json` documented. They don’t require any additional configuration (unless you would like to skip them).


## Coverage [static-coverage]

Static tests cover the following resources:

1. Sample event for a data stream - verification if the file uses only documented fields.


## Running static tests [static-running]

Static tests don’t require the {{stack}} to be up and running. Simply navigate to the package’s root folder (or any sub-folder under it) and run the following command.

```bash
elastic-package test static
```

If you want to run pipeline tests for **specific data streams** in a package, navigate to the package’s root folder (or any sub-folder under it) and run the following command.

```bash
elastic-package test static --data-streams <data stream 1>[,<data stream 2>,...]
```
