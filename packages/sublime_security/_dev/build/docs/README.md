# Sublime Security

Sublime Security is a programmable, AI-powered, cloud email security platform for Microsoft 365 and Google Workspace environments. It is used to block email attacks such as phishing, BEC, malware, threat hunt and auto-triage user reports.

The Sublime Security integration collects data for Audit, Email Message(MDM Schema) and Message Event logs using REST API and AWS-S3 or AWS-SQS:

- REST API mode - Sublime Security integration collects and parses data from the Sublime Security REST APIs.
- AWS S3 polling mode - Sublime Security writes data to S3 and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- AWS S3 SQS mode - Sublime Security writes data to S3, S3 pushes a new object notification to SQS, Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple Agents can be used in this mode.

## Data streams

The Sublime Security integration collects three types of logs:

**[Audit](https://docs.sublime.security/reference/listeventsinauditlog)** - Captures detailed records of all significant actions and changes within the platform, including changes to email security policies, user access to email data, and modifications to email configurations, ensuring traceability and compliance for all operations.

**[Email Message](https://docs.sublime.security/docs/export-message-mdms)** - Represents the flow of individual emails through the platform, including sender and recipient details, spam filtering outcomes, and overall email disposition, helping to secure and analyze email communication.

**[Message Event](https://docs.sublime.security/reference/getmessage-1)** - Represents document specific actions taken on emails, like spam detection or rule applications, providing detailed insights into how the platform processes and protects email communications.

## Requirements

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html#_minimum_requirements).

## Setup

### To collect data from the Sublime Security API:

#### Step 1: Go to Platform
- Visit the [Sublime Security Platform](https://platform.sublime.security/) and select `API` in Developers section.

#### Step 2: Generating the API Key
- Retrieve your `API Key`. This key will be used further in the Elastic integration setup to authenticate and access different Sublime Security Logs.
- `Base URL` of Sublime Security is also required for configuring integration.

### To collect data from AWS S3 Bucket or AWS SQS:

#### For AWS S3 Bucket, follow the below steps:
- Create an Amazon S3 bucket. Refer to the link [here](https://docs.aws.amazon.com/AmazonS3/latest/userguide/create-bucket-overview.html).
- User can set the parameter "Bucket List Prefix" according to the requirement.

#### For AWS SQS, follow the below steps:
1. If data forwarding to an AWS S3 Bucket hasn't been configured, then first set up an AWS S3 Bucket as mentioned in the above documentation.
2. To set up an SQS queue, follow "Step 1: Create an Amazon SQS queue" mentioned in the [Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
  - While creating an SQS Queue, please provide the same bucket ARN that has been generated after creating an AWS S3 Bucket.
3. Set up event notifications for a S3 bucket. Follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
  - Users have to set the prefix parameter the same as the S3 Bucket List Prefix as created earlier. (for example, `exports/sublime_platform_audit_log/` for a audit data stream).
  - Select the event type as s3:ObjectCreated:*, select the destination type SQS Queue, and select the queue that has been created in Step 2.

**Note**:
  - Credentials for the above AWS S3 and SQS input types should be configured using the [link](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html#aws-credentials-config).
  - Data collection via AWS S3 Bucket and AWS SQS are mutually exclusive in this case.
  - You can configure a global SQS queue for all data streams or a local SQS queue for each data stream. Configuring data stream specific SQS queues will enable better performance and scalability. Data stream specific SQS queues will always override any global queue definitions for that specific data stream.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type Sublime Security.
3. Click on the "Sublime Security" integration from the search results.
4. Click on the "Add Sublime Security" button to add the integration.
5. Enable the Integration to collect logs via AWS S3 or API input.
6. Under the AWS S3 input, there are two types of inputs: using AWS S3 Bucket or using SQS.
7. Add all the required integration configuration parameters, including API Key, Interval, Initial Interval and Page Size for API input and Access Key, Secret Key and Session Token for AWS input type to enable data collection.
8. Click on "Save and continue" to save the integration.

**Note**:
- The Base URL for Sublime Security cloud customers is `https://api.platform.sublimesecurity.com`. Depending on your type of deployment, yours may be different.
- For SSO users, in addition to access key ID and secret access key, the session token is required to configure integration. For IAM users, the session token is optional and not required.

## Logs reference

### Audit

This is the `audit` dataset.

#### Example

{{event "audit"}}

{{fields "audit"}}

### Email Message

This is the `email_message` dataset.

#### Example

{{event "email_message"}}

{{fields "email_message"}}

### Message Event

This is the `message_event` dataset.

#### Example

{{event "message_event"}}

{{fields "message_event"}}
