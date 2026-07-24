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

Deploys `ElasticFederatedIdentityRole` — an IAM role that trusts Elastic's central `cloud_connectors` role (`arn:aws:iam::254766567737:role/cloud_connectors`) via cross-account `sts:AssumeRole` with an ExternalId scoped to the Elastic deployment and stack UUID.

The base role includes `SecurityAudit` (AWS managed policy) which covers read access to most AWS services and is shared by all integrations. Each integration package appends its own **`AWS::IAM::Policy` resource** via RFC 6902 `add` operations — using unique, package-namespaced resource names to avoid collisions when multiple integrations are enabled simultaneously.

Aligned with `deploy/cloudformation/cloud-connectors-remote-role.yml` in `elastic/cloudbeat` (PR #7422).

**Parameters:**

| Parameter           | Default                                              | Description                                                                |
|---------------------|------------------------------------------------------|----------------------------------------------------------------------------|
| `ElasticResourceId` | _(required)_                                         | Elastic resource ID; combined with the stack UUID to form the ExternalId   |
| `ElasticRoleARN`    | `arn:aws:iam::254766567737:role/cloud_connectors`    | Elastic super-role ARN. Change only for non-production Elastic environments |

**Outputs:**

| Output       | Description                                                                                |
|--------------|--------------------------------------------------------------------------------------------|
| `RoleArn`    | ARN of the created role. Paste into Kibana when configuring the integration.               |
| `ExternalId` | Full ExternalId string (`<ElasticResourceId>-<StackUUID>`). Paste into Kibana.             |
| `StackId`    | CloudFormation stack ID. Store in Kibana to construct stack-update URLs for later patches. |

**Patch strategy — collision avoidance:**

Each package adds a uniquely named `AWS::IAM::Policy` resource rather than appending to inline `Policies` on the role. This means multiple packages can be enabled on the same stack without any JSON Patch path conflicts:

| Package                  | Input             | Patch file                                               | Resource added                    |
|--------------------------|-------------------|----------------------------------------------------------|-----------------------------------|
| `cloud_security_posture` | `cis_aws`         | `aws-federated-identity-account.cloudformation.patches.json`      | `ElasticCSPMSupplementalPolicy`  |
| `cloud_security_posture` | `cis_eks`         | `aws-federated-identity-account-eks.cloudformation.patches.json`  | `ElasticKSPMEKSPolicy`           |
| `cloud_security_posture` | `vuln_mgmt_aws`   | `aws-federated-identity-account-cnvm.cloudformation.patches.json` | `ElasticCNVMPolicy`              |
| `cloud_asset_inventory`  | `asset_inventory_aws` | `aws-federated-identity-account.cloudformation.patches.json`  | `ElasticCAISupplementalPolicy`   |

**Packages using this blueprint:**
- `cloud_security_posture` — CIS AWS (`cis_aws`), CIS EKS (`cis_eks`), CNVM (`vuln_mgmt_aws`) inputs
- `cloud_asset_inventory` — AWS Asset Inventory (`asset_inventory_aws`) input

## Adding a new blueprint

1. Create `blueprints/<provider>/<trust-model>/<scope>.<format>.json` with the minimal base structure.
2. Integration patches should add new top-level `AWS::IAM::Policy` (or equivalent) resources with unique names rather than modifying shared arrays, to avoid patch collisions.
3. Document the blueprint in this README with its parameters, outputs, and which packages use it.
