# IaC Blueprints

This directory contains the **canonical IaC base blueprints** consumed by the `cloud-iac-provisioner` renderer.

## How it works

Each integration package declares an `iac_blueprints` entry in its manifest:

```yaml
iac_blueprints:
  - id: aws/federated-identity/account
    format: cloudformation
    patches: iac/aws-federated-identity-account.cloudformation.patches.json
```

The `cloud-iac-provisioner` renderer:

1. Loads the canonical blueprint from `blueprints/<id>.<format>.json` (this directory).
2. Applies RFC 6902 patches from every enabled package's `iac/<...>.patches.json` file in order.
3. Emits one deployable IaC artifact covering all enabled integrations — one IAM role, one stack, one deploy.

## File naming convention

```
blueprints/<provider>/<trust-model>/<scope>.<format>.json
```

Mirrors the blueprint `id` field with the `format` appended:

| Blueprint ID                       | Format          | File                                                              |
|------------------------------------|-----------------|-------------------------------------------------------------------|
| `aws/federated-identity/account`   | cloudformation  | `blueprints/aws/federated-identity/account.cloudformation.json`  |

## Available blueprints

### `aws/federated-identity/account` (CloudFormation)

**File:** [`aws/federated-identity/account.cloudformation.json`](aws/federated-identity/account.cloudformation.json)

Deploys `ElasticCloudConnectorsRole` — an IAM role that trusts Elastic's central `cloud_connectors` role (`arn:aws:iam::254766567737:role/cloud_connectors`) via cross-account `sts:AssumeRole` with an ExternalId scoped to the Elastic deployment and stack. The role has empty `ManagedPolicyArns` and `Policies` arrays as patch targets — integration packages append their required policies via RFC 6902 `add` operations.

Aligned with `deploy/cloudformation/cloud-connectors-remote-role.yml` in `elastic/cloudbeat`.

**Parameters:**

| Parameter         | Default                                              | Description                                                                |
|-------------------|------------------------------------------------------|----------------------------------------------------------------------------|
| `ElasticResourceId` | _(required)_                                       | Elastic resource ID; combined with the stack UUID to form the ExternalId   |
| `ElasticRoleARN`  | `arn:aws:iam::254766567737:role/cloud_connectors`    | Elastic super-role ARN. Change only for non-production Elastic environments |

**Outputs:** `RoleArn`, `ExternalId`

**Packages using this blueprint:**
- `cloud_security_posture` — CIS AWS (`cis_aws`), CIS EKS (`cis_eks`), CNVM (`vuln_mgmt_aws`) inputs
- `cloud_asset_inventory` — AWS Asset Inventory (`asset_inventory_aws`) input

## Adding a new blueprint

1. Create `blueprints/<provider>/<trust-model>/<scope>.<format>.json` with the minimal base structure.
2. Ensure it has empty arrays or placeholder collections at every path that integration patches will `add` to.
3. Document the blueprint in this README with its parameters, outputs, and which packages use it.
