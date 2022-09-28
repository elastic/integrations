# Kubernetes Security Posture Management 

This integration periodically monitors and compares Kubernetes infrastructure against security best practices defined by CIS to help security, DevOps, and DevSecOps personnel to: 

1. Identify and remediate misconfigurations 
2. Understand the overall security posture of their Kubernetes clusters both- individually and holistically 

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

This Integration does not currently support the security posture assessment of:

1. Google GKE
2. Azure AKS 
3. Red Hat Openshift 
4. Amazon EKS with AWS Fargate nodes

## Permissions 

This integration requires access to node files, node processes, and the Kubernetes api-server therefore, it assumes the agent will be installed as a [DaemonSet](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/) with the proper [Roles](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#role-and-clusterrole) and [RoleBindings](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#rolebinding-and-clusterrolebinding) attached.

If deploying this integration on an [Amazon EKS cluster](https://docs.aws.amazon.com/eks/latest/userguide/what-is-eks.html), an IAM user with programmatic access and specific permissions is required to make AWS API calls. When creating the IAM user, please make sure to create and attach an [IAM policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_create.html) to it that has the following set of permissions: 


```yaml
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
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

If the necessary credentials aren't provided, EKS clusters won't get evaluated. 

## Leader election

To collect cluster level data (compared to node level information) the integration makes use of the [leader election](https://www.elastic.co/guide/en/fleet/master/kubernetes_leaderelection-provider.html) mechanism.
This mechanism assures that the cluster level data is collected by only one of the agents running as a part of the DaemonSet and not by all of them.

Cluster level data example: List of the running pods.
Node level data example: kubelet configuration.

## Deployment

#### Deploy the Elastic agent

Just like every other integration, the KSPM integration requires an Elastic agent to be deployed. 

See agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/running-on-kubernetes-managed-by-fleet.html).

Note, this integration can only be added to Elastic agents with versions 8.4 or higher.


## EKS Managed Deployment

The following AWS authentication options are avaliable to run KSPM integration
1. Access Key & Secret
2. ARN Role
3. Credentials File

### Access Key & Secret
Get the credentials from `~/.aws/credentials` file.
Copy the `aws_access_key_id` and `aws_secret_access_key` from the profile.
#### Session Token
When using a session token it is required to provide a new session token every `duration`.
For example: to generate session token that last for one hour, run `aws sts get-session-token --duration-seconds 3600`.

### ARN Role
To assume a different role, make sure that the target role has a `trusted-entity`
```json
{
    {
        "Effect": "Allow",
        "Principal": {
            "AWS": "arn:aws:iam::{AWS_ACCOUNT}:assumed-role/{AWS_ROLE}/{EC2_INSTANCE}"
        },
        "Action": "sts:AssumeRole",
        "Condition": {}
    }
}
```

## Shared Credentials File
To use a shared credentials file:
1. Make sure the credentials file exist on the file-system of the pod
2. In case the file has multiple profiles or the profile is not `default` specify the profile name in "Credential Profile Name" field.

### Example with Kustomize
1. Go to your Kibna UI `app/fleet/agents` and add new agent `Add Agent`
2. Download the kubernetes manifests
3. Copy the `~/.aws/credentials`: `cp ~/.aws/credentials .`
4. Apply the following Kustomization `kubectl apply -k kustomize.yaml`
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: kube-system

resources:
  # download the manifests from Kibana UI
  - elastic-agent-managed-kubernetes.yaml 

# make sure to
# cp ~/.aws/credentials .
secretGenerator:
  - behavior: create
    name: aws-credentials
    files:
      - credentials
patches:
  - patch: |-
      - op: add
        path: /spec/template/spec/volumes/-
        value:
          name: aws-credentials
          secret:
            defaultMode: 420
            secretName: aws-credentials
      - op: add
        path: /spec/template/spec/containers/0/volumeMounts/-
        value:
          name: aws-credentials
          mountPath: /etc/.aws
    target:
      kind: DaemonSet 
```
 
