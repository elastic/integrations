---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/data-stream-spec.html
---

# data_stream [data-stream-spec]

Data stream assets, including ingest pipelines, field definitions, metadata, and sample events.

**required**

Included from the package-spec repository. This will update when the spec is updated.

```yaml
spec:
  additionalContents: false
  totalContentsLimit: 500
  contents:
  - description: Folder containing a single data stream definition
    type: folder
    pattern: '^([a-z0-9]{2}|[a-z0-9][a-z0-9_]+[a-z0-9])$'
    forbiddenPatterns:
      # Avoid collision with ingest pipeline created by fleet, see https://github.com/elastic/package-spec/issues/699
      - '^integration$'
    required: true
    additionalContents: false
    contents:
    - description: A data stream's manifest file
      type: file
      contentMediaType: "application/x-yaml"
      sizeLimit: 5MB
      name: "manifest.yml"
      required: true
      $ref: "./manifest.spec.yml"
    - description: Folder containing field definitions
      type: folder
      name: fields
      required: true
      $ref: "./fields/spec.yml"
    - description: Folder containing agent-related definitions
      type: folder
      name: agent
      required: false
      additionalContents: false
      $ref: "./agent/spec.yml"
    - description: Folder containing Elasticsearch assets
      type: folder
      name: elasticsearch
      additionalContents: false
      contents:
      - description: Folder containing Elasticsearch ILM Policy Definition
        type: folder
        name: ilm
        additionalContents: false
        contents:
        - description: Supporting ILM policy definitions in YAML
          type: file
          pattern: '^.+\.yml$'
          # TODO Determine if special handling of `---` is required (issue: https://github.com/elastic/package-spec/pull/54)
          contentMediaType: "application/x-yaml; require-document-dashes=true"
          required: false
        - description: Supporting ILM policy definitions in JSON
          type: file
          pattern: '^.+\.json$'
          contentMediaType: "application/json"
          required: false
      - description: Folder containing Elasticsearch Ingest Node pipeline definitions
        type: folder
        name: ingest_pipeline
        additionalContents: false
        contents:
        - description: Supporting ingest pipeline definitions in YAML
          type: file
          pattern: '^.+\.yml$'
          # TODO Determine if special handling of `---` is required (issue: https://github.com/elastic/package-spec/pull/54)
          contentMediaType: "application/x-yaml; require-document-dashes=true"
          required: false
          allowLink: true
          $ref: "../../integration/elasticsearch/pipeline.spec.yml"
        - description: Supporting ingest pipeline definitions in JSON
          type: file
          pattern: '^.+\.json$'
          contentMediaType: "application/json"
          required: false
          allowLink: true
          $ref: "../../integration/elasticsearch/pipeline.spec.yml"
    - description: Sample event file
      type: file
      name: "sample_event.json"
      contentMediaType: "application/json"
      required: false
    - description: Folder containing testing related files and sub-folders
      type: folder
      name: "test"
      required: false
    - description: Folder containing development resources
      type: folder
      name: _dev
      required: false
      visibility: private
      $ref: "./_dev/spec.yml"
    - description: File containing routing rules definitions (technical preview)
      type: file
      contentMediaType: "application/x-yaml"
      name: "routing_rules.yml"
      required: false
      $ref: "./routing_rules.spec.yml"
    - description: File containing lifecycle configuration (technical preview)
      type: file
      contentMediaType: "application/x-yaml"
      name: "lifecycle.yml"
      required: false
      $ref: "lifecycle.spec.yml"

versions:
  - before: 3.0.0
    patch:
      - op: remove
        path: "/contents/0/contents/3/contents/1/contents/0/$ref" # remove ingest pipeline validation as yaml
      - op: remove
        path: "/contents/0/contents/3/contents/1/contents/1/$ref" # remove ingest pipeline validation as json
  - before: 2.10.0
    patch:
      - op: remove
        path: "/contents/0/contents/8" # remove lifecycle definition
  - before: 2.9.0
    patch:
      - op: remove
        path: "/contents/0/contents/7" # remove routing_rules file definition
```
