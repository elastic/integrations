# Cloud Asset Discovery

## Overview

The Cloud Asset Discovery integration helps you discover and track all the resources in your cloud environment across AWS, Google Cloud Platform (GCP), and Microsoft Azure. 

## What data does this integration collect?

Once you connect your cloud accounts, this integration automatically finds and lists your cloud services and assets, such as:

- **AWS**: S3 buckets, EC2 instances, EKS clusters, and more.
- **GCP**: Cloud Storage buckets, Compute Engine instances, Kubernetes clusters, and more.
- **Azure**: Virtual Machines, Blob Storage, Azure Kubernetes Service (AKS), and more.

[View the full list of supported services for discovery](https://github.com/elastic/cloudbeat/blob/main/internal/inventory/ASSETS.md).

### Use cases

- **Automatic Asset Discovery**: Skip the manual work. Get an up-to-date inventory of all your cloud resources in one place.
- **Complete Cloud Visibility**: View assets across AWS, GCP, and Azure in a unified interface.
- **Better Security Oversight**: Know exactly what resources you have so you can make sure they are secure and properly configured.
- **Track All Your Cloud Resources**: Get a full inventory of your cloud assets, across all accounts and providers, with minimal effort.
- **Keep an Eye on Security and Compliance**: Make sure your resources are set up correctly and follow best practices.
- **Additional Cloud Asset Context**: Gain more context about your cloud assets to help in triaging detected threats effectively.

## What do I need to use this integration?

* The Cloud Asset Discovery integration is available to all {{ecloud}} users. On-premise deployments require an [appropriate subscription](https://www.elastic.co/pricing) level.
* Cloud Asset Discovery supports only the AWS, GCP, and Azure commercial cloud platforms. Government cloud platforms are not supported. To request support for other platforms, [open a GitHub issue](https://github.com/elastic/kibana/issues/new/choose).

## How do I deploy this integration?

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **Cloud Asset Discovery**.
3. Select the **Cloud Asset Discovery** integration and add it.
4. Add all the required integration configuration parameters, including Access Token, Interval, Initial Interval and Page Size to enable data collection.
5. Save the integration.

For more information on Cloud security solutions, refer to [Cloud Security](docs-content://solutions/security/cloud.md)