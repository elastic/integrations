---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/agent-version-conditions.html
---

# Agent version conditions [agent-version-conditions]

::::{note}
Agent version conditions require Kibana 9.4 or later.
::::

Integration packages can declare version constraints on Elastic Agent to ensure compatibility when features depend on a specific agent version. There are two ways to define these constraints:

- **Package-level**: the entire package requires a minimum agent version.
- **Input template-level**: individual configuration blocks are conditionally rendered based on the agent version.

Both mechanisms are used together when a package supports multiple agent versions but uses newer capabilities when available.


## Package-level agent version condition [package-level-agent-version-condition]

Use the `conditions.agent.version` field in `manifest.yml` to require a minimum Elastic Agent version for the entire package. Fleet will warn users if enrolled agents in a policy do not meet this requirement. Agents incompatible with the version condition will not run the integration.

```yaml
conditions:
  kibana
    version: '^9.4.0'
  agent:
    version: "^9.3.0"
```

Use this approach when **all** inputs in the package rely on agent capabilities introduced in a specific version.

::::{note}
`conditions.agent.version` requires Kibana 9.4 or later.
::::


## Input template-level agent version condition [input-template-level-agent-version-condition]

Use the `{{#semverSatisfies}}` Handlebars helper in `.hbs` stream templates to conditionally include configuration blocks based on the agent version. This allows a single package to serve agents at different versions by rendering version-appropriate configuration.

The helper uses `_meta.agent.version` as the version variable and accepts a [semver](https://semver.org/) range as the constraint:

```handlebars
{{#semverSatisfies _meta.agent.version "^9.3.0"}}
program: |
  ...CEL program using features available in agent 9.3.0+...
{{/semverSatisfies}}
```

Use this approach when only **some** inputs or configuration blocks require a newer agent, so that older agents continue to work with the rest of the package.

**Example — auth0 CEL input** (`data_stream/logs/agent/stream/cel.yml.hbs`):

```handlebars
redact:
  fields:
    - client_secret
{{#semverSatisfies _meta.agent.version "^9.3.0"}}
program: |
  state.with(
    post(state.url + "/oauth/token", "application/json", {
      "client_id": state.client_id,
      "client_secret": state.client_secret,
      ...
    })
  )
{{/semverSatisfies}}
```

Here the `program:` block is only included in the rendered config when the agent version is `^9.3.0`. Agents on earlier versions receive the configuration without the `program:` key.


## How Fleet handles agent version conditions [how-fleet-handles-agent-version-conditions]

### Package-level conditions

When a policy is created or updated, Fleet evaluates the `conditions.agent.version` constraint against the versions of enrolled agents in the policy. If an agent does not satisfy the constraint, Fleet surfaces a warning in the Fleet UI indicating the version mismatch.
The policy assigned to the earlier version of agents will not include the incompatible integrations.

### Input template-level conditions

Fleet renders `.hbs` templates for each enrolled agent, passing the agent's version as `_meta.agent.version`. The `{{#semverSatisfies}}` helper evaluates the semver constraint at render time:

- If the agent version **satisfies** the constraint, the block is included in the rendered configuration sent to that agent.
- If the agent version **does not satisfy** the constraint, the block is omitted from the rendered configuration.

This means agents at different versions within the same policy each receive a configuration tailored to their capabilities, without requiring separate packages or policy templates.


## When to use each approach [when-to-use]

| Situation | Recommended approach |
|---|---|
| All inputs require a specific agent version | Package-level (`conditions.agent.version` in `manifest.yml`) |
| Only one input type uses new agent capabilities | Input template-level (`{{#semverSatisfies}}` in `.hbs`) |
| Package has both old and new agent support | Input template-level, so older agents still work |
| CEL input uses new built-in functions or keywords | Input template-level on the `program:` block |
