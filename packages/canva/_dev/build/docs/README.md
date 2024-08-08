# Canva

[Canva](https://www.canva.com/) is an online graphic design platform used for creating social media graphics, presentations, posters, documents, and other visual content. Canva provides [Audit logs](https://www.canva.dev/docs/audit-logs/) that contain records of user activies in Canva, such as installing a [Canva App](https://www.canva.com/your-apps/), [exporting a design](https://www.canva.com/help/download-or-purchase/) for download, or a user changing their [account settings](https://www.canva.com/help/account-settings/). These logs can be useful for compliance audits, monitoring for unauthorized activity, and other matters that require details about the creation, access, and deletion of data in Canva.

**NOTE**:
- Audit logs are available for organizations that use Canva Enterprise.
- Canva starts generating Audit logs when an organization upgrades their account to Canva Enterprise and will start logging events for a brand once it joins the Canva Enterprise account.

The Canva integration can be used in two different modes to collect data:
- **AWS S3 polling mode** - Canva writes data to S3 and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- **AWS S3 SQS mode** - Canva writes data to S3, S3 pushes a new object notification to SQS, Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple Agents can be used in this mode.

## Data streams

The Canva integration collects Audit logs in an audit data stream.

**Audit** contains the information about the user activies in Canva. The user changing account settings, installing Canva app, managing teams, and groups information can be logged through the Audit logs.

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

## Setup

### To stream data from Canva to the AWS S3 Bucket:

- Follow the link [here](https://www.canva.dev/docs/audit-logs/setup/) to forward your Audit log data from Canva to the AWS S3 bucket.
- Canva add events to your S3 bucket every minute as a gzipped archive containing JSONL content and requires PutObject permission on the S3 bucket.
- It store the files in hourly folders, in the format orgId/yyyy/MM/dd/HH.

### To collect data from AWS S3 Bucket, follow the below steps:

- Create an Amazon S3 bucket. Refer to the link [here](https://docs.aws.amazon.com/AmazonS3/latest/userguide/create-bucket-overview.html).
- The default value of the "Bucket List Prefix" should be empty. However, the user can set the parameter "Bucket List Prefix" according to the requirement.

### To collect data from AWS SQS, follow the below steps:

1. If data forwarding to an AWS S3 Bucket hasn't been configured, then first set up an AWS S3 Bucket as mentioned in the above documentation.
2. To set up an SQS queue, follow "Step 1: Create an Amazon SQS queue" mentioned in the [Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
  - While creating an SQS Queue, please provide the same bucket ARN that has been generated after creating an AWS S3 Bucket.
3. Set up event notifications for an S3 bucket. Follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
  - Users have to set the prefix parameter the same as the S3 Bucket List Prefix as created earlier. (for example, `log/` for a log data stream.)
  - Select the event type as s3:ObjectCreated:*, select the destination type SQS Queue, and select the queue that has been created in Step 2.

**Note**:
  - Credentials for the above AWS S3 and SQS input types should be configured using the [link](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html#aws-credentials-config).
  - Data collection via AWS S3 Bucket and AWS SQS are mutually exclusive in this case.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type Canva
3. Click on the "Canva" integration from the search results.
4. Click on the Add Canva Integration button to add the integration.
5. While adding the integration, if you want to collect logs via AWS S3, then you have to put the following details:
   - Collect logs via S3 Bucket toggled on
   - Access Key ID
   - Secret Access Key
   - Bucket ARN
   - Session Token

   or if you want to collect logs via AWS SQS, then you have to put the following details:
   - Collect logs via S3 Bucket toggled off
   - Queue URL
   - Secret Access Key
   - Access Key ID
   - Session Token

6. Save the integration.

**NOTE**:
There are other input combination options available for the AWS S3 and AWS SQS, please check [here](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html).

## Logs Reference

### Audit

This is the `Audit` dataset.

#### Example

{{event "audit"}}

{{fields "audit"}}
