---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/kibana-spec.html
---

# kibana [kibana-spec]

The integration’s {{kib}} assets, like dashboards, visualizations, {{ml}} modules, etc.

**required**

Included from the package-spec repository. This will update when the spec is updated.

```yaml
spec:
  additionalContents: false
  contents:
  - description: Folder containing Kibana dashboard assets
    type: folder
    name: dashboard
    required: false
    contents:
    - description: A dashboard asset file
      type: file
      contentMediaType: "application/json"
      pattern: '^{PACKAGE_NAME}-.+\.json$'
      forbiddenPatterns:
        - '^.+-(ecs|ECS)\.json$' # ECS suffix is forbidden
  - description: Folder containing Kibana visualization assets
    type: folder
    name: visualization
    required: false
    contents:
    - description: A visualization asset file
      type: file
      contentMediaType: "application/json"
      pattern: '^{PACKAGE_NAME}-.+\.json$'
      forbiddenPatterns:
        - '^.+-(ecs|ECS)\.json$' # ECS suffix is forbidden
  - description: Folder containing Kibana saved search assets
    type: folder
    name: search
    required: false
    contents:
    - description: A saved search asset file
      type: file
      contentMediaType: "application/json"
      pattern: '^{PACKAGE_NAME}-.+\.json$'
      forbiddenPatterns:
        - '^.+-(ecs|ECS)\.json$' # ECS suffix is forbidden
  - description: Folder containing Kibana map assets
    type: folder
    name: map
    required: false
    contents:
    - description: A map asset file
      type: file
      contentMediaType: "application/json"
      pattern: '^{PACKAGE_NAME}-.+\.json$'
      forbiddenPatterns:
        - '^.+-(ecs|ECS)\.json$' # ECS suffix is forbidden
  - description: Folder containing Kibana lens assets
    type: folder
    name: lens
    required: false
    contents:
      - description: A lens asset file
        type: file
        contentMediaType: "application/json"
        pattern: '^{PACKAGE_NAME}-.+\.json$'
        forbiddenPatterns:
          - '^.+-(ecs|ECS)\.json$' # ECS suffix is forbidden
  - description: Folder containing Kibana index pattern assets
    type: folder
    name: "index_pattern"
    required: false
    contents:
    - description: An index pattern asset file
      type: file
      contentMediaType: "application/json"
      pattern: '^.+\.json$'
  - description: Folder containing rules
    type: folder
    name: "security_rule"
    required: false
    contents:
    - description: An individual rule file for the detection engine
      type: file
      contentMediaType: "application/json"
      pattern: '^.+\.json$'
  - description: Folder containing CSP rule templates
    type: folder
    name: "csp_rule_template"
    required: false
    contents:
    - description: An individual CSP rule template file for the cloud security posture management solution
      type: file
      contentMediaType: "application/json"
      pattern: '^.+\.json$'
  - description: Folder containing ML module assets
    type: folder
    name: ml_module
    required: false
    contents:
      - description: An ML module asset file
        type: file
        contentMediaType: "application/json"
        pattern: '^{PACKAGE_NAME}-.+\.json$'
  - description: Folder containing Kibana tags
    type: folder
    name: tag
    required: false
    contents:
    - description: A dashboard tag file
      type: file
      contentMediaType: "application/json"
      pattern: '^{PACKAGE_NAME}-.+\.json$'
  - description: Folder containing Osquery pack assets
    type: folder
    name: osquery_pack_asset
    required: false
    contents:
    - description: An osquery pack asset file
      type: file
      contentMediaType: "application/json"
      pattern: '^{PACKAGE_NAME}-.+\.json$'
  - description: Folder containing Osquery saved queries
    type: folder
    name: osquery_saved_query
    required: false
    contents:
    - description: An osquery saved query file
      type: file
      contentMediaType: "application/json"
      pattern: '^{PACKAGE_NAME}-.+\.json$'
  - description: File containing saved object tag definitions for assets
    type: file
    contentMediaType: "application/x-yaml"
    name: "tags.yml"
    required: false
    $ref: "./tags.spec.yml"
  - description: Folder containing Kibana SLO assets
    type: folder
    name: slo
    required: false
    contents:
    - description: An SLO asset file
      type: file
      contentMediaType: "application/json"
      pattern: '^{PACKAGE_NAME}-.+\.json$'
      forbiddenPatterns:
        - '^.+-(ecs|ECS)\.json$' # ECS suffix is forbidden
versions:
  - before: 3.5.0
    patch:
      - op: remove
        path: "/contents/13" # remove SLO definitions
  - before: 2.10.0
    patch:
      - op: remove
        path: "/contents/12" # remove tags definition
```
