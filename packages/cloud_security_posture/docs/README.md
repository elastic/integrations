# Security Posture Management

Maintain the **confidentiality, integrity, and availability** of your data in the cloud by continuously identifying configuration risks in your cloud infrastructure. 

## Cloud Security Posture Management (CSPM)

CSPM will enumerate the cloud services your leverage, like S3, EC2, RDS, ..., and evaluate them against industry-defined secure configuration standards to identify and remediate misconfigurations like: 

- Publicly exposed storage buckets 
- IAM Users without MFA enabled 
- Networking objects that allow ingress to remote server administration ports (22, 3389, etc.)

And much more! Check out our getting started guide for step-by-step guidance on how to get started with CSPM. 

## Kubernetes Security Posture Management (KSPM)

KSPM allows you to identify the various resources that make up your Kubernetes cluster, like nodes, pod security policies, containers, ..., and evaluate them against industry-defined secure configuration standards to identify and remediate misconfigurations like: 

- Kubelete servers that allow anonymous Auth
- Unencrypted traffic to load balancers
- PSPs that enable the admission of privileged containers 

And much more! Check out our getting started guide for step-by-step guidance on how to get started with KSPM. 

Using K/CSPM

After deploying the CSPM and or KSPM integration, the pages described in the table below will begin to get populated with security posture data. Please read the use cases section for CSPM and KSPM, respectively get an idea of how you can use the pages below to interact with your security posture data. 

| Page             | Description                                                                                                                                         |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Posture Dashboard | The posture dashboard provides an overview of the security posture of both Cloud Accounts and Kubernetes clusters monitored. You can access the posture dashboard via the dashboards section of the security solution. Please read the [posture dashboard documentation](https://ela.st/posture-dashboard) to learn more.                                                |
| Findings          | Findings communicate the configuration risks discovered in your environments. The findings page will always display the most up-to-date configuration risks found. You can access the findings page in the main navigation pane of the security solution. Please read the [findings documentation](https://ela.st/findings) to learn more. |
| Benchmark Rules   | Benchmarks hold the configuration rules that are used to assess your specific environments for secure configuration. You can access benchmark rules in the `Manage` section of the security solution under `CLOUD SECURITY POSTURE.` To learn more, please read the [benchmark rules documentation](https://ela.st/configuration-rules)                                                                                                                                                            |

As questions come up, check out the [KSPM FAQ](https://ela.st/kspm-faq) or reach out to use directly in our [community slack workspace](https://elasticstack.slack.com/) in the #security or #cloud-security-product channels. 