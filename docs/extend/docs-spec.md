---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/docs-spec.html
---

# docs [docs-spec]

The built integration README file.

**required**

Included from the package-spec repository. This will update when the spec is updated.

```yaml
spec:
  additionalContents: false
  contents:
  - description: Main README file
    type: file
    contentMediaType: "text/markdown"
    name: "README.md"
    required: true
  - description: Other README files (can be used by policy templates)
    type: file
    contentMediaType: "text/markdown"
    pattern: '^.+.md'
    required: false
```
