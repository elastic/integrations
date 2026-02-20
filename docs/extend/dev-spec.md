---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/dev-spec.html
---

# _dev [dev-spec]

Development resources.

**required**

Included from the package-spec repository. This will update when the spec is updated.

```yaml
spec:
  additionalContents: false
  developmentFolder: true
  contents:
    - description: Folder containing resources related to package benchmarks.
      type: folder
      name: benchmark
      required: false
      $ref: "./benchmark/spec.yml"
    - description: Folder containing resources related to building the package.
      type: folder
      name: build
      required: false
      $ref: "./build/spec.yml"
    - description: Folder containing configuration related to deploying the package's service(s) required for testing scenarios.
      type: folder
      name: deploy
      required: false
      $ref: "./deploy/spec.yml"
    - description: Folder containing configuration related test configuration.
      type: folder
      name: test
      required: false
      $ref: "./test/spec.yml"
    - description: Folder containing shared files.
      type: folder
      name: shared
      $ref: "../../integration/spec.yml"
```
