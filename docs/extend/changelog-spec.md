---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/changelog-spec.html
---

# changelog.yml [changelog-spec]

The integration’s changelog.

**required**

Included from the package-spec repository. This will update when the spec is updated.

```yaml
##
## Describes the specification for the package's CHANGELOG file
##
spec:
  # Everything under here follows JSON schema (https://json-schema.org/), written as YAML for readability
  type: array
  items:
    type: object
    additionalProperties: false
    properties:
      version:
        description: Package version.
        $ref: "./manifest.spec.yml#/definitions/version"
      changes:
        description: List of changes in package version.
        type: array
        items:
          type: object
          additionalProperties: false
          properties:
            description:
              description: Description of change.
              type: string
              examples:
              - "Fix broken template"
            type:
              description: Type of change.
              type: string
              enum:
              - "breaking-change"
              - "bugfix"
              - "enhancement"
            link:
              description: Link to issue or PR describing change in detail.
              type: string
              examples:
              - "https://github.com/elastic/integrations/pull/550"
          required:
          - description
          - type
          - link
    required:
    - version
    - changes
```
