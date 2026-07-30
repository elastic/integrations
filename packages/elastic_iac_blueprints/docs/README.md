# Elastic IaC Blueprints

This package is a **versioned bundle of canonical Infrastructure-as-Code (IaC) base blueprints** consumed by the `cloud-iac-provisioner` renderer. Unlike other packages it is **not installed** into Kibana, Elasticsearch, or the Elastic Agent — the registry serves it, and the provisioner fetches its files at render time.

## How it works

Each integration package declares `iac_blueprints` entries that reference a blueprint by `id` + `format` and point at an RFC 6902 patch file:

```yaml
iac_blueprints:
  - id: aws/federated-identity/account
    format: cloudformation
    patches: iac/aws-federated-identity-account.cloudformation.patches.json
```

The `cloud-iac-provisioner` renderer:

1. Fetches the canonical blueprint for `(id, format)` from **this package in the registry**:
   `GET /package/elastic_iac_blueprints/<version>/blueprints/<id>.<format>.<ext>`
2. Applies the RFC 6902 patches from every enabled integration's `iac/*.patches.json` file, in a stable order.
3. Emits one deployable IaC artifact covering all enabled integrations — one IAM role, one stack, one deploy.

## File layout

```
blueprints/<provider>/<trust-model>/<scope>.<format>.<ext>
```

mirrors the blueprint `id` (`<provider>/<trust-model>/<scope>`) with the `format` and file extension appended:

| Blueprint ID                      | Format         | File                                                             |
|-----------------------------------|----------------|-----------------------------------------------------------------|
| `aws/federated-identity/account`  | cloudformation | `blueprints/aws/federated-identity/account.cloudformation.json` |

## Versioning

- **Additive changes** (a new anchor, a new blueprint id, a new format file) are backwards compatible — a newer canonical is a superset, so patches authored against an older version still apply. These bump the package version.
- **Breaking changes** (restructuring a role, renaming a path patches target, changing a trust shape) ship as a **new `@vN` blueprint id** that coexists with the old one, rather than mutating it in place.
- The provisioner resolves the version **latest-behind-a-canary**: it tracks the newest published version but promotes it to the fleet only after a compatibility guard (re-applying every registered package's patches) and a canary. An integration that depends on a newly added anchor may pin a floor via `requires`.

## Available blueprints

### `aws/federated-identity/account` (CloudFormation)

**File:** [`blueprints/aws/federated-identity/account.cloudformation.json`](blueprints/aws/federated-identity/account.cloudformation.json)

Deploys `ElasticFederatedIdentityRole` — an IAM role that trusts Elastic's central `cloud_connectors` role via cross-account `sts:AssumeRole` with an ExternalId scoped to the Elastic deployment and stack UUID. Each enabled integration appends its own `AWS::IAM::Policy` resource via RFC 6902 `add` operations, using package-namespaced resource names to avoid collisions when multiple integrations are enabled together.
