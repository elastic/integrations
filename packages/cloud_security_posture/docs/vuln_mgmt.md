# Elastic Vulnerability Management for Cloud

Elastic Vulnerability Management for Cloud allows you to identify vulnerabilities in your cloud workloads. It accomplishes this by periodically taking a snapshot of the running cloud workloads and scanning those snapshots for vulnerabilities. As vulnerabilities are discovered, they appear in the vulnerabilities tab of the findings page in the security solution. Please refer to`Elastic Vulnerability Management for Cloud documentation for further information.

We recommend reading through this entire readme before getting started with Elastic Vulnerability Management for Cloud.


## Getting started guide

For in-depth, step-by-step instructions to help you get started with Elastic Vulnerability Management for Cloud, please read through our getting started guide.

## Using Elastic Vulnerability Management for Cloud

As soon as you install this integration, the pages described in the table below will begin to populate with vulnerability data. For detailed instructions on how to use these pages for improving your cloud vulnerability status, please refer to the "Use Cases" section of the Elastic Vulnerability Management for Cloud documentation.

| Page                            | Description                                                                                                                                                                                                                                                                                                                                                |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Vulnerabilities tab in Findings | Lists the vulnerabilities discovered in your cloud workloads. The most recent vulnerabilities discovered from the last scan will always be displayed on this page. You can access this page by clicking on the Findings subsection in the main navigation pane of the security solution. Please read the vulnerabilities page documentation to learn more. |


## Compatibility

The integration only supports vulnerability management for [Amazon EC2](https://aws.amazon.com/ec2/) cloud workloads.

Container workloads (Amazon EKS) and other public cloud providers such as Google Cloud Platform (GCP) and Microsoft Azure are not currently supported. 

A version of elastic agent 8.8 or higher is required for integration.


## Integration Requirements

@TODO 

Are there any additional permissions required to launch a CloudFormation template in a customer's AWS account?

Is it just that the customer must log into their AWS account in the same browser session?

Can a CTA be provided if the customer has not logged into their AWS account?  
