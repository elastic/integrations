# Cloud Asset Discovery

The Cloud Asset Discovery integration helps you discover and track all the resources in your cloud environment across AWS, Google Cloud Platform (GCP), and Microsoft Azure. Once you connect your cloud accounts, this integration automatically finds and lists your cloud services and assets, such as:

- **AWS**: S3 buckets, EC2 instances, EKS clusters, and more.
- **GCP**: Cloud Storage buckets, Compute Engine instances, Kubernetes clusters, and more.
- **Azure**: Virtual Machines, Blob Storage, Azure Kubernetes Service (AKS), and more.

> ⚠️ (BETA) Please note: Multiple cloud providers per policy are not supported. Please select only one.

[View the full list of supported services for discovery](https://github.com/elastic/cloudbeat/blob/main/internal/inventory/ASSETS.md).

### Why Use Cloud Asset Discovery?

- **Automatic Asset Discovery**: Skip the manual work. Get an up-to-date inventory of all your cloud resources in one place.
- **Complete Cloud Visibility**: View assets across AWS, GCP, and Azure in a unified interface.
- **Better Security Oversight**: Know exactly what resources you have so you can make sure they are secure and properly configured.

### What You Can Do:

- **Track All Your Cloud Resources**: Get a full inventory of your cloud assets, across all accounts and providers, with minimal effort.
- **Keep an Eye on Security and Compliance**: Make sure your resources are set up correctly and follow best practices.
- **Additional Cloud Asset Context**: Gain more context about your cloud assets to help in triaging detected threats effectively.

### How It Works:

1. **Connect**: Provide read-only access to your cloud accounts (AWS, GCP, Azure).
2. **Discover**: The integration will perform an inventory of all cloud resources every 24 hours.
3. **View**: View the discovered assets via our out-of-the-box dashboard.

### Getting Started:

You can get started by adding this integration and providing the necessary access. You can also follow the step-by-step getting started guide [here](https://ela.st/cloud-asset-inventory-guide)
