---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/agent-version-conditions.html
---

# Agent version conditions [agent-version-conditions]

Integration packages sometimes depend on capabilities that are only available in newer versions of Elastic Agent. A single Fleet policy can manage agents on different versions at the same time, for example during a rolling upgrade, so a package must keep working on every agent version it supports.

To handle agent version differences, gate the version-specific configuration inside the input template with the `{{#semverSatisfies}}` Handlebars helper, and always provide a fallback for older agents. See [Input template-level agent version condition](#input-template-level-agent-version-condition).

::::{important}
The package-level `conditions.agent.version` field in `manifest.yml` is **deprecated**. Do not use it in new packages, and migrate existing packages away from it. See [Deprecated: package-level agent version condition](#package-level-agent-version-condition).
::::


## Input template-level agent version condition [input-template-level-agent-version-condition]

Use the `{{#semverSatisfies}}` Handlebars helper in `.hbs` stream templates to conditionally include configuration blocks based on the agent version. This allows a single package version to serve agents at different versions by rendering version-appropriate configuration.

::::{note}
The `_meta.agent.version` variable requires Kibana 9.4 or later.
::::

The helper uses `_meta.agent.version` as the version variable and accepts a [semver](https://semver.org/) range as the constraint:

```handlebars
program: |
  {{#semverSatisfies _meta.agent.version "^9.3.0"}}
  // program using features available in agent 9.3.0+
  ...
  {{else}}
  // fallback program for agents older than 9.3.0
  ...
  {{/semverSatisfies}}
```

Always provide an `{{else}}` branch when the block is required for the input to work. Every branch of a `{{#semverSatisfies}}` condition should produce a valid configuration, so that a single package version stays runnable on all supported agent versions. When the gated setting is optional, such as a new opt-in option, the `{{else}}` branch can be omitted: older agents then render the configuration without it.

**Example — auth0 CEL input** (`data_stream/logs/agent/stream/cel.yml.hbs`):

```handlebars
redact:
  fields:
    - client_secret
program: |
  {{#semverSatisfies _meta.agent.version "^9.3.0"}}
  // Uses post() built-in available in agent 9.3.0+
  state.with(
    post(state.url + "/oauth/token", "application/json", {
      "client_id": state.client_id,
      "client_secret": state.client_secret,
      ...
    })
  )
  {{else}}
  // Fallback for agents older than 9.3.0
  state.with(
    request("POST", state.url + "/oauth/token").with({
      "body": {
        "client_id": state.client_id,
        "client_secret": state.client_secret,
        ...
      }
    }).do_request()
  )
  {{/semverSatisfies}}
```

The `{{else}}` branch ensures that agents on earlier versions still receive a complete, runnable `program:` block.

**Example — opt-in option** (`data_stream/entity/agent/stream/entity-analytics.yml.hbs`): `use_minimal_state` is only understood by agent 9.5.0 and later. Older agents render the configuration without it.

```handlebars
{{#if use_minimal_state}}
{{#semverSatisfies _meta.agent.version ">=9.5.0"}}
use_minimal_state: true
{{/semverSatisfies}}
{{/if}}
```


## Stack-level gating with `conditions.kibana.version` [stack-level-gating]

Use `conditions.kibana.version` to restrict which Kibana versions a package version can be installed on. This is the right mechanism when the package relies on stack features, such as new Fleet UI capabilities or Kibana saved object types:

```yaml
conditions:
  kibana:
    version: '^9.4.0'
```

`conditions.kibana.version` gates **stack installation**. It does not change what an individual agent runs. It is not a substitute for handling agent version differences: use input template-level conditions for that.


## Deprecated: package-level agent version condition [package-level-agent-version-condition]

::::{warning}
`conditions.agent.version` in `manifest.yml` is deprecated. Package validation emits warning [SVR00012](https://github.com/elastic/package-spec/blob/main/docs/validations.md) starting with package-spec 3.6.7, and the field is rejected as an error for packages that use `format_version` 3.7.0 or later.
::::

```yaml
# Deprecated, do not use
conditions:
  kibana:
    version: '^9.4.0'
  agent:
    version: "^9.3.0"
```

### Timeline

| Stage | package-spec | Behavior |
|---|---|---|
| Migration window | 3.6.7 | `elastic-package lint` and `check` report warning `SVR00012` when a package declares `conditions.agent.version`. |
| Removal | 3.7.0 | The field is no longer part of the spec. Packages with `format_version` 3.7.0 or later that declare it fail validation. |

During the migration window you can suppress the warning for a package in its `validation.yml`, while you work on the migration:

```yaml
errors:
  exclude_checks:
    - SVR00012
```

### Why it is deprecated

- **It is a hard gate.** For agents that do not satisfy the range, Fleet removes the whole integration from that agent's policy.
- **It conflicts with mixed-agent-version policies.** One policy must work across old and new agents at the same time, for example during rolling upgrades or rollbacks.
- **It causes data gaps.** Agents below the minimum version stop collecting data from the integration until they are upgraded, even if most of the integration would have worked on them.
- **Its semantics differ from `conditions.kibana.version`.** The Kibana condition gates stack installation, while the agent condition changes the runtime policy of each agent. Using the same `conditions` structure for both is misleading.

### How to migrate

1. Remove `conditions.agent.version` from `manifest.yml`.
2. Wrap the configuration that needs the newer agent in `{{#semverSatisfies _meta.agent.version "<range>"}}` in the affected stream templates.
3. Make sure the rendered configuration is valid for every supported agent version: add an `{{else}}` branch when the gated block is required, or omit the option when it is optional.
4. If the feature only affects the Fleet UI (for example `var_groups`) and has no effect on the rendered template, no template change is needed. Older agents ignore the unused variables.
5. Bump the package version and add a changelog entry.

**Example — `use_cloud_connectors`** (`aws_bedrock`): the `use_cloud_connectors` option is only understood by agent 9.4.0 and later. Instead of excluding older agents from the integration, render the option only for agents that support it.

Before (`manifest.yml`):

```yaml
conditions:
  kibana:
    version: "^9.6.0"
  agent:
    version: "^9.4.0"
```

After (`manifest.yml`):

```yaml
conditions:
  kibana:
    version: "^9.6.0"
```

After (`data_stream/runtime/agent/stream/stream.yml.hbs`):

```handlebars
{{#if supports_identity_federation}}
{{#semverSatisfies _meta.agent.version ">=9.4.0"}}
use_cloud_connectors: {{supports_identity_federation}}
{{/semverSatisfies}}
{{/if}}
```

Agents older than 9.4.0 receive a configuration without `use_cloud_connectors` and keep collecting data with the other authentication options.

### Testing

Add policy tests that confirm the rendered output is valid for both the minimum supported agent version and the current agent version.

::::{note}
`elastic-package test policy` renders the base policy, where `_meta.agent.version` is not set. The rendered output therefore corresponds to the `{{else}}` branch (the fallback for older agents). Verify the newer-agent branch separately, for example with a system test against a current agent.
::::

### Cases without a viable fallback

Some configurations have no reasonable `{{else}}` fallback. For example, the `auth.aws:` authentication in the `aws` package has no equivalent in older agents that supports `role_arn`, shared credentials, and instance roles. The recommended approach for these cases is still being decided, and this section will be updated once it is.


## How Fleet handles agent version conditions [how-fleet-handles-agent-version-conditions]

### Input template-level conditions

Fleet renders `.hbs` templates for each enrolled agent, passing the agent's version as `_meta.agent.version`. Fleet re-renders the policy when an agent reports a new version on check-in, producing a new per-agent policy revision. The `{{#semverSatisfies}}` helper evaluates the semver constraint at render time:

- If the agent version **satisfies** the constraint, the block is included in the rendered configuration sent to that agent.
- If the agent version **does not satisfy** the constraint, the block is omitted, or the `{{else}}` branch is rendered if there is one.

This means agents at different versions within the same policy each receive a configuration tailored to their capabilities, without requiring separate packages or policy templates.

### Package-level conditions (deprecated)

When a policy is created or updated, Fleet evaluates `conditions.agent.version` against the versions of the enrolled agents in the policy. For agents that do not satisfy the constraint, Fleet surfaces a warning in the Fleet UI and the policy rendered for those agents does not include the integration.


## Upgrade and downgrade considerations [upgrade-downgrade-considerations]

When an agent binary is upgraded or downgraded, the new binary starts with a cached copy of the previously rendered policy. The agent runs this cached policy until the first successful check-in, at which point Fleet re-renders the template against the new version and returns a fresh policy revision.

For most forward upgrades within a major version this is harmless: newer agents accept older rendered configs while they wait for the first check-in. The risky cases are:

- **Downgrades**: the cached policy was rendered for a newer agent and may reference inputs, processors, or built-ins not available in the older binary.
- **Major-version upgrades** that remove an input option or processor the cached rendering depends on.

To limit the impact:

- Prefer gating optional, additive options, so that a configuration rendered for a different agent version still starts.
- Keep the `{{else}}` fallback valid and runnable on the oldest agent version the package supports.
- Do not rely on `conditions.agent.version` to protect version-dependent features. It removes the integration from older agents entirely, which causes data gaps during rolling upgrades.


## When to use each approach [when-to-use]

| Situation | Recommended approach |
|---|---|
| Only one input or option uses new agent capabilities | Input template-level (`{{#semverSatisfies}}` in `.hbs`) |
| Package has both old and new agent support | Input template-level with a valid `{{else}}` fallback, so older agents still work |
| CEL input uses new built-in functions or keywords | Input template-level on the `program:` block |
| New option is opt-in and older agents can simply ignore it | Input template-level, without an `{{else}}` branch |
| Package requires a Kibana or Fleet feature | `conditions.kibana.version` in `manifest.yml` |
| Package requires a minimum agent version for all inputs | Input template-level gating with a fallback. Do not use `conditions.agent.version` (deprecated). |
