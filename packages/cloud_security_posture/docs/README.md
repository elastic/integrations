# Security Posture Management

Use the Security Posture Management integration to maintain the **confidentiality, integrity, and availability** of your data in the cloud by continuously identifying configuration risks in your cloud infrastructure, like publicly exposed storage buckets and overly permissive networking objects. Read below to learn more about the components that make up security posture management; CSPM & KSPM. 

## Cloud Security Posture Management (CSPM)

CSPM discovers and evaluates the services in your cloud environment, like storage, compute, IAM, and more, against hardening guidelines defined by the Center for Internet Security (CIS) to help you identify and remediate configurations risks like:

- Publicly exposed storage buckets 
- IAM Users without MFA enabled 
- Networking objects that allow ingress to remote server administration ports (22, 3389, etc.)

And much more! For a complete overview of CSPM, including step-by-step getting started guidance, check out [CSPM's documentation](https://ela.st/cspm).

## Kubernetes Security Posture Management (KSPM)

KSPM discovers and evaluates the components that make up your Kubernetes cluster against hardening guidelines defined by the [Center for Internet Security](https://www.cisecurity.org/) (CIS) to help you identify and remediate configurations risks like:

- Kubelete servers that allow anonymous auth
- Unencrypted traffic to load balancers
- Admission of containers with `allowPrivilegeEscalation` permissions 

And much more! Check out the [KSPM getting started guide](https://ela.st/kspm-get-started) for step-by-step guidance on how to get started with KSPM. 

## Using C/KSPM

To use both CSPM and KSPM, you'll have to deploy each integration separately. After deploying either one or both integrations, the pages described below will begin to get populated with security posture data. Please read the respective use cases section for [CSPM](https://ela.st/cspm-use-cases) and [KSPM](https://ela.st/kspm-use-cases) for step-by-step instructions on how to use these pages to get insight into and improve your cloud security posture.

| Page             | Description                                                                                                                                         |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Posture Dashboard | The posture dashboard provides an overview of the security posture of both Cloud accounts and Kubernetes clusters monitored. You can access the posture dashboard via the dashboards section of the security solution. Please read the [posture dashboard documentation](https://ela.st/posture-dashboard) to learn more.                                                |
| Findings          | Findings communicate the configuration risks discovered in your environments. The findings page will always display the most up-to-date configuration risks found. You can access the findings page in the main navigation pane of the security solution. Please read the [findings documentation](https://ela.st/findings) to learn more. |
| Benchmark Rules   | Benchmarks hold the configuration rules that are used to assess your specific environments for secure configuration. You can access benchmark rules in the `Manage` section of the security solution under `CLOUD SECURITY POSTURE.` To learn more, please read the [benchmark rules documentation](https://ela.st/configuration-rules)                                                                                                                                                            |

As questions come up, check out the [KSPM FAQ](https://ela.st/kspm-faq) or reach out to use directly in our [community slack workspace](https://elasticstack.slack.com/) in the `#security` or `#cloud-security` channels. 