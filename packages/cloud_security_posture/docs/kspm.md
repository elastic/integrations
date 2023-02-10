# Kubernetes Security Posture Management 

The Kubernetes Security Posture Management (KSPM) integration allows you to identify and remediate configuration risks in the various components that make up your Kubernetes cluster. It does this by evaluating the various components of your cluster against secure configuration guidelines, as defined by the Center for Internet Security (CIS), to identify configuration risks. When configuration risks are discovered, [findings](https://ela.st/findings) are generated that highlight the misconfigured resource and include step-by-step remediation instructions. Please read the [KSPM documentation](https://ela.st/kspm) for an overview of KSPM. 

We recommend reading through this entire readme before getting started with KSPM. 

## Getting started with KSPM

For in-depth, step-by-step instructions to help you get started with KSPM, please read through [our getting started guide](https://ela.st/kspm-get-started). 

## Using KSPM  

After you deploy this integration, the pages described in the table below will begin to get populated with security posture data. Please read the ["Use Cases"](https://ela.st/kspm-use-cases) section of the KSPM documentation for step-by-step instructions on how to use these pages to get insight into and improve the security posture of your Kubernetes clusters. 


| Page             | Description                                                                                                                                         |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Posture Dashboard | The posture dashboard provides an overview of the security posture of both Cloud Accounts and Kubernetes clusters monitored. You can access the posture dashboard via the dashboards section of the security solution. Please read the [posture dashboard documentation](https://ela.st/posture-dashboard) to learn more.                                                |
| Findings          | Findings communicate the configuration risks discovered in your environments. The findings page will always display the most up-to-date configuration risks found. You can access the findings page in the main navigation pane of the security solution. Please read the [findings documentation](https://ela.st/findings) to learn more. |
| Benchmark Rules   | Benchmarks hold the configuration rules that are used to assess your specific environments for secure configuration. You can access benchmark rules in the `Manage` section of the security solution under `CLOUD SECURITY POSTURE.` To learn more, please read the [benchmark rules documentation](https://ela.st/configuration-rules)                                                                                                                                                            |

As questions come up, check out the [KSPM FAQ](https://ela.st/kspm-faq) or reach out to use directly in our [community slack workspace](https://elasticstack.slack.com/) in the #security or #cloud-security channels. 