# Amazon Security Lake

This [Amazon Security Lake](https://aws.amazon.com/security-lake/) integration helps you analyze security data, so you can get a more complete understanding of your security posture across the entire organization. With Security Lake, you can also improve the protection of your workloads, applications, and data.

Security Lake automates the collection of security-related log and event data from integrated AWS services and third-party services. It also helps you manage the lifecycle of data with customizable retention and replication settings. Security Lake converts ingested data into Apache Parquet format and a standard open-source schema called the Open Cybersecurity Schema Framework (OCSF). With OCSF support, Security Lake normalizes and combines security data from AWS and a broad range of enterprise security data sources.

The Amazon Security Lake integration can be used in two different modes to collect data:
- AWS S3 polling mode: Amazon Security Lake writes data to S3, and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- AWS S3 SQS mode: Amazon Security Lake writes data to S3, S3 sends a notification of a new object to SQS, the Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple agents can be used in this mode.

## Compatibility

This module follows the latest OCSF Schema Version **v1.0.0-rc.3**.

## Data streams

The Amazon Security Lake integration collects logs for the below [AWS services](https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html) combined in a data stream named event:

| Source                              | Class Name                                          |
|-------------------------------------|-----------------------------------------------------|
| CloudTrail Lambda Data Events       | API Activity                                        |
| CloudTrail Management Events        | API Activity, Authentication, or Account Change     |
| CloudTrail S3 Data Events           | API Activity                                        |
| Route 53                            | DNS Activity                                        |
| Security Hub                        | Security Finding                                    |
| VPC Flow Logs                       | Network Activity                                    |

### **NOTE**:
- The Amazon Security Lake integration supports events collected from [AWS services](https://docs.aws.amazon.com/security-lake/latest/userguide/internal-sources.html).

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data from the S3 bucket and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.11.0**.

## Setup

### To collect data from an AWS S3 bucket or AWS SQS, follow the below steps:

1. To enable and start Amazon Security Lake, follow the steps mentioned here: [`https://docs.aws.amazon.com/security-lake/latest/userguide/getting-started.html`](https://docs.aws.amazon.com/security-lake/latest/userguide/getting-started.html).
2. Above mentioned steps will create and provide required details such as IAM roles/AWS role ID, external id and queue url to configure AWS Security Lake Integration.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type Amazon Security Lake.
3. Click on the "Amazon Security Lake" integration from the search results.
4. Click on the Add Amazon Security Lake Integration button to add the integration.
5. By default collect logs via S3 Bucket toggle will be off and collect logs for AWS SQS.
6. While adding the integration, if you want to collect logs via AWS SQS, then you have to put the following details:
   - queue url
   - collect logs via S3 Bucket toggled off
   - Shared Credential File Path and Credential Profile Name / Access Key Id and Secret Access Key
   - role ARN
   - external id

   or if you want to collect logs via AWS S3, then you have to put the following details:
   - bucket arn
   - collect logs via S3 Bucket toggled on
   - Shared Credential File Path and Credential Profile Name / Access Key Id and Secret Access Key
7. If user wants to access security lake by Assuming Role then add Role ARN or if user want to access resources of another account using Role ARN then add Role ARN and external ID.

**NOTE**: There are other input combination options available, please check [here](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html).

## Logs reference

### Event

This is the `Event` dataset.

#### Example

{{fields "event"}}