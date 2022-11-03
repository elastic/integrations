# Kubernetes Security Posture Management 

The Kubernetes Security Posture Management (KSPM) integration allows you to identify and remediate configuration risks in the various components that make up your Kubernetes cluster. It does this by evaluating the various components of your cluster against secure configuration guidelines, as defined by the Center for Internet Security (CIS), in order to identify configuration risks. When configuration risks are discovered, [findings](https://ela.st/findings-8-5) are generated that tell you exactly what is misconfigured and how you can remediate it. Please read through the [KSPM documentation](https://ela.st/kspm) for an overview of KSPM. 

We recommend reading through this entire readme before getting started with KSPM. 


## Getting started guide

For in-depth, step-by-step instructions to help you get started with KSPM, please read through [our getting started guide](https://ela.st/getting-started-with-kspm). 

## Using KSPM  

After you install this integration, the pages described in the table below will begin to get populated with security posture data. Please read the ["Use Cases"](https://ela.st/kspm-use-cases-8-5) section of the KSPM documentation for step-by-step instructions on how to use these pages to get insight into and improve the security posture of your Kubernetes clusters. 

| Page             | Description                                                                                                                                         |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Posture Dashboard | The posture dashboard provides an overview of the security posture of all Kubernetes clusters monitored. You can access the posture dashboard via the dashboards section of the security solution. Please read the [posture dashboard documentation](https://ela.st/posture-dashboard-8-5) to learn more.                                                |
| Findings          | Findings communicate the configuration risks discovered in your clusters. The findings page will always display the most up-to-date configuration risks discovered. You can access the findings page in the main navigation pane of the security solution. Please read the [findings documentation](https://ela.st/findings-8-5) to learn more. |
| Benchmark Rules   | Benchmark rules are used to assess your Kubernetes clusters for secure configuration. You can access benchmark rules in the `Manage` section of the security solution under `CLOUD SECURITY POSTURE.` To learn more, please read the [benchmark rules documentation](https://ela.st/benchmark-rules-8-5)                                                                                                                                                   |


## Compatibility

This integration is tested with Kubernetes 1.21.x and currently supports the security posture assessment of:

1. [Unmanaged/Vanilla Kubernetes clusters](https://kubernetes.io/)
2. [Amazon EKS clusters](https://aws.amazon.com/eks/)

This integration has not been tested on 

1. Amazon EKS on AWS Outposts

This integration does not currently support the security posture assessment of the managed kubernetes services below:

1. Google GKE
2. Azure AKS 
3. Red Hat Openshift 
4. Amazon EKS with AWS Fargate nodes

The integration supports **elastic agent** version 8.5 and above.

## Integration Requirments 

The KSPM integration requires access to node files, node processes, and the Kubernetes api-server therefore, it assumes the agent will be installed as a [DaemonSet](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/) with the proper [Roles](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#role-and-clusterrole) and [RoleBindings](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#rolebinding-and-clusterrolebinding) attached.


If deploying this integration on an [Amazon EKS cluster](https://docs.aws.amazon.com/eks/latest/userguide/what-is-eks.html), you will additionally need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

### AWS Credentials


AWS credentials are required for running the KSPM integration in your EKS clusters.

There are a few ways to provide AWS credentials:

* Use access keys directly
* Use temporary security credentials
* Use a shared credentials file 
* Use an IAM role Amazon Resource Name (ARN)]

#### Use access keys directly

Access keys are long-term credentials for an IAM user or the AWS account root user.
To use access keys as credentials, you need to provide:

* `Access Key ID`: The first part of the access key.
* `Secret Access Key`: The second part of the access key.

For more details refer to [AWS Access Keys and Secret Access Keys](https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html#access-keys-and-secret-access-keys).

#### Use temporary security credentials

Temporary security credentials can be configured in AWS to last for some period of time.
They consist of an access key ID, a secret access key, and a security token, which is 
typically returned using `GetSessionToken`.
IAM users with multi-factor authentication (MFA) enabled need to submit an MFA code
while calling `GetSessionToken`.
For more details refer to [Temporary Security Credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html).

You can use AWS CLI to generate temporary credentials. 
For example, you would use `sts get-session-token` if you have MFA enabled:

```js
aws sts get-session-token --serial-number arn:aws:iam::1234:mfa/your-email@example.com --duration-seconds 129600 --token-code 123456
```

Then, use the response to provide the following information to the KSPM integration:

* `Access Key ID`: The first part of the access key.
* `Secret Access Key`: The second part of the access key.
* `Session Token`: A token is required when using temporary security credentials.

Because temporary security credentials are short-term, after they expire you will need
to generate new ones and manually update the integration's configuration to continue posture evaluations. There will be downtime in coverage if the configuration is not updated with the new credentials before the old ones expire. 


#### Use a shared credentials file

If you use different credentials for different tools or applications, you can use profiles to 
configure multiple access keys in the same configuration file.
For more details, refer to [Create Shared Credentials File](https://docs.aws.amazon.com/sdkref/latest/guide/file-format.html#file-format-creds).

Instead of providing the `Access Key ID` and `Secret Access Key` directly to the integration,
you will provide the following values to reference the access keys in the shared credentials file:

* `Credential Profile Name`: The profile name in the shared credentials file.
* `Shared Credential File`: The directory of the shared credentials file.

**Note**: If you don't provide values for all keys, the integration will use these defaults:
- If none of the `Access Key ID`, `Secret Access Key`, and `ARN Role` options are provided, then the integration will check for `Credential Profile Name.`
- If there is no `Credential Profile Name` given, the integration will use the default profile.
- If `Shared Credential File` is empty, the integration will use the default directory.
  - For Linux or Unix, the shared credentials file is located at `~/.aws/credentials`.
- The integration will use the EC2 attached role if no values are provided. 

#### Use an IAM role Amazon Resource Name (ARN)

An IAM role ARN is an IAM identity you can create in your AWS account. You define the role's permissions.
A role does not have standard long-term credentials such as passwords or access keys.
Instead, when you assume a role, it provides you with temporary security credentials for your session.
An IAM role's ARN can be used to specify which AWS IAM role to use to generate temporary credentials..
For more details refer to [AssumeRole API documentation](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html).

To use an IAM role's ARN, you need to provide either a credential profile or
access keys along with the `ARN Role` option.
`ARN Role` is used to specify which AWS IAM role to assume for generating temporary credentials.

Note: If `ARN Role` is given, the integration will check if access keys are given.
If they are not given, the integration will check for a credential profile name.
If neither is given, the integration will try to assume with the EC2 attached role. 


### AWS Permissions

Specific AWS permissions are required for an IAM user to make the necessary AWS API calls.
To enable the KSPM integration to collect the configuration state of all necessary services,
make sure to grant the following permissions:

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


JSON object of an IAM Policy with the permissions above: 

```json
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

## Leader election

To collect cluster level data (compared to node level information) the integration makes use of the [leader election](https://www.elastic.co/guide/en/fleet/master/kubernetes_leaderelection-provider.html) mechanism.
This mechanism assures that the cluster-level data is collected by only one of the agents running as a part of the DaemonSet and not all.

Cluster level data example: List of the running pods.
Node level data example: kubelet configuration.


