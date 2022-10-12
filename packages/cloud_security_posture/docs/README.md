# Kubernetes Security Posture Management 

This integration periodically monitors and compares Kubernetes infrastructure against security best practices defined by CIS to help security, DevOps, and DevSecOps personnel to: 

1. Identify and remediate misconfigurations 
2. Understand the overall security posture of their Kubernetes clusters both- individually and holistically 


We recommend reading through this entire readme before getting started with KSPM. You can also jump to the section that you're specifically interested in using the quick links below. 

* [Getting Started Guide](#getting-started-guide)
* [Integration Assets](#integration-assets)
* [Compatibility](#compatibility)
* [Integration Requirments](#requirments)
* [Leader election](#leader-election)


## Getting started guide

For in-depth, step-by-step, instructions to help you get started with KSPM, please read through [our getting started guide](https://ela.st/getting-started-with-kspm). 

## Integration Assets 

After this integration has been installed for the first time, the following assets will get created and made available in the Security solution UI: 

| Asset             | Description                                                                                                                                         |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Posture Dashboard | The posture dashboard provides an overview of the security posture of all Kubernetes clusters monitored                                                |
| Findings          | Findings communicate the outcome of a specific resource being evaluated with a specific rule. All latest findings are viewable on the findings page |
| Benchmark Rules   | Benchmark rules are used to assess Kubernetes resources for secure configuration. Benchmark rules are viewable on the Benchmark page                                                                                                                                                   |

## Compatibility

This integration is tested with Kubernetes 1.21.x and currently supports the security posture assessment of:

1. [Unmanaged/Vanilla Kubernetes clusters](https://kubernetes.io/)
2. [Amazon EKS clusters](https://aws.amazon.com/eks/)

This integration has not been tested on 

1. Amazon EKS on AWS Outposts

This Integration does not currently support the security posture assessment of of the managed kubernetes services below:

1. Google GKE
2. Azure AKS 
3. Red Hat Openshift 
4. Amazon EKS with AWS Fargate nodes

## Requirments 

The KSPM integration requires access to node files, node processes, and the Kubernetes api-server therefore, it assumes the agent will be installed as a [DaemonSet](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/) with the proper [Roles](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#role-and-clusterrole) and [RoleBindings](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#rolebinding-and-clusterrolebinding) attached.


If deploying this integration on an [Amazon EKS cluster](https://docs.aws.amazon.com/eks/latest/userguide/what-is-eks.html), you will additionally need:

* [**AWS Credentials**](#aws-credentials) to connect with your AWS account.
* [**AWS Permissions**](#aws-permissions) to make sure the user you're using to connect has permission to share the relevant data.

### AWS Credentials


AWS credentials are required for running the KSPM integration in your EKS clusters.

There are a few ways to provide AWS credentials:

* [Use access keys directly](#use-access-keys-directly)
* [Use temporary security credentials](#use-temporary-security-credentials)
* [Use a shared credentials file](#shared-credentials-file)
* [Use an IAM role Amazon Resource Name (ARN)](#use-an-iam-role-amazon-resource-name-arn)

#### Use access keys directly

Access keys are long-term credentials for an IAM user or the AWS account root user.
To use access keys as credentials, you need to provide:

* `access_key_id`: The first part of the access key.
* `secret_access_key`: The second part of the access key.

For more details see [AWS Access Keys and Secret Access Keys](https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html#access-keys-and-secret-access-keys).

#### Use temporary security credentials

Temporary security credentials can be configured in AWS to last for some period of time.
They consist of an access key ID, a secret access key, and a security token, which is 
typically returned using `GetSessionToken`.
IAM users with multi-factor authentication (MFA) enabled need to submit an MFA code
while calling `GetSessionToken`.
For more details see [Temporary Security Credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html).

You can use AWS CLI to generate temporary credentials. 
For example, you would use `sts get-session-token` if you have MFA enabled:

```js
aws sts get-session-token --serial-number arn:aws:iam::1234:mfa/your-email@example.com --duration-seconds 129600 --token-code 123456
```

Then, use the response to provide the following information to the KSPM integration:

* `access_key_id`: The first part of the access key.
* `secret_access_key`: The second part of the access key.
* `session_token`: A token required when using temporary security credentials.

Because temporary security credentials are short term, after they expire you will need
to generate new ones and manually update the package configuration to continue posture evaluations.
This will cause down time in coverage if the configuration is not updated with the new credentials before the old ones expire. 

#### Use a shared credentials file

If you use different credentials for different tools or applications, you can use profiles to 
configure multiple access keys in the same configuration file.
For more details see [Create Shared Credentials File](https://docs.aws.amazon.com/sdkref/latest/guide/file-format.html#file-format-creds)

Instead of providing the `access_key_id` and `secret_access_key` directly to the integration,
you will provide the following values to reference the access keys in the shared credentials file:

* `credential_profile_name`: The profile name in shared credentials file.
* `shared_credential_file`: The directory of the shared credentials file.

**Note**: If you don't provide values for all keys, the integration will use these defaults:
- If `access_key_id`, `secret_access_key` and `role_arn` are all not provided, then the package will check for `credential_profile_name`.
- If there is no `credential_profile_name` given, the default profile will be used.
- If `shared_credential_file` is empty, the default directory will be used.
  - For Linux, or Unix, the shared credentials file is located at `~/.aws/credentials`.

#### Use an IAM role Amazon Resource Name (ARN)

An IAM role ARN is an IAM identity that you can create in your AWS account. You determine what the role has permission to do.
A role does not have standard long-term credentials such as a password or access keys associated with it.
Instead, when you assume a role it provides you with temporary security credentials for your role session.
IAM role ARN can be used to specify which AWS IAM role to assume to generate temporary credentials.
For more details see [AssumeRole API documentation](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html).

To use an IAM role's ARN, you need to provide either a [credential profile](#use-a-shared-credentials-file) or
[access keys](#use-access-keys-directly) along with the `role_arn` advanced option.
`role_arn` is used to specify which AWS IAM role to assume for generating temporary credentials.

Note: If `role_arn` is given, the package will check if access keys are given.
If they are not given, the package will check for a credential profile name.
If neither is given, the default credential profile will be used. 


### AWS Permissions

Specific AWS permissions are required for an IAM user to make specific AWS API calls.
To enable the KSPM integration to collect metrics and logs from all necssary services,
make sure these permissions are given:

* `ecr:GetRegistryPolicy`,
* `eks:ListTagsForResource`
* `elasticloadbalancing:DescribeTags`
* `ecr-public:DescribeRegistries`
* `ecr:DescribeRegistry`
* `elasticloadbalancing:DescribeLoadBalancerPolicyTypes`
* `ecr:ListImages`
* `ecr-public:GetRepositoryPolicy`
* `elasticloadbalancing:DescribeLoadBalancerAttributes`
* `elasticloadbalancing:DescribeLoadBalancers`
* `ecr-public:DescribeRepositories`
* `eks:DescribeNodegroup`
* `ecr:DescribeImages`
* `elasticloadbalancing:DescribeLoadBalancerPolicies`
* `ecr:DescribeRepositories`
* `eks:DescribeCluster`
* `eks:ListClusters`
* `elasticloadbalancing:DescribeInstanceHealth`
* `ecr:GetRepositoryPolicy`

<details>
<summary>IAM Policy JSON object</summary>

```js

{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecr:GetRegistryPolicy",
                "eks:ListTagsForResource",
                "elasticloadbalancing:DescribeTags",
                "ecr-public:DescribeRegistries",
                "ecr:DescribeRegistry",
                "elasticloadbalancing:DescribeLoadBalancerPolicyTypes",
                "ecr:ListImages",
                "ecr-public:GetRepositoryPolicy",
                "elasticloadbalancing:DescribeLoadBalancerAttributes",
                "elasticloadbalancing:DescribeLoadBalancers",
                "ecr-public:DescribeRepositories",
                "eks:DescribeNodegroup",
                "ecr:DescribeImages",
                "elasticloadbalancing:DescribeLoadBalancerPolicies",
                "ecr:DescribeRepositories",
                "eks:DescribeCluster",
                "eks:ListClusters",
                "elasticloadbalancing:DescribeInstanceHealth",
                "ecr:GetRepositoryPolicy"
            ],
            "Resource": "*"
        }
    ]
}

```

</details>


## Leader election

To collect cluster level data (compared to node level information) the integration makes use of the [leader election](https://www.elastic.co/guide/en/fleet/master/kubernetes_leaderelection-provider.html) mechanism.
This mechanism assures that the cluster level data is collected by only one of the agents running as a part of the DaemonSet and not by all of them.

Cluster level data example: List of the running pods.
Node level data example: kubelet configuration.