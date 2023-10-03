# Trellix EDR Cloud

This [Trellix EDR Cloud](https://www.trellix.com/en-us/products/edr.html) integration enables your detected threats and suspicious network data to be sent to Elastic Security via Amazon S3. When integrated with Elastic Security, this valuable data can be leveraged within Elastic for threat protection, detection, and incident response.

The Trellix EDR Cloud integration can be used in two different modes to collect data:
- AWS S3 polling mode: Trellix EDR Cloud writes data to S3, and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- AWS S3 SQS mode: Trellix EDR Cloud writes data to S3, S3 sends a notification of a new object to SQS, the Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple agents can be used in this mode.

## Compatibility

This module has been tested against the latest (June 05, 2023) Trellix EDR Cloud version.

## Data streams

The Trellix EDR Cloud integration collects logs for the following seventeen events:

| Event Type      |
|-----------------|
| API             |
| Context Changed |
| DNS Query       |
| EPP             |
| File            |
| Image Loaded    |
| Named Pipe      |
| Network         |
| Process         |
| RegKey          |
| RegValue        |
| Scheduled Task  |
| Script Executed |
| Service         |
| SysInfo         |
| User            |
| WMI             |


**NOTE**: The Trellix EDR Cloud integration collects logs for the above mentioned events, but we have combined all of those in one data stream named `event`.

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

The minimum **kibana.version** required is **8.9.0**.

## Setup

### To collect data from an AWS S3 bucket, follow the below steps:

1. Considering you already have an AWS S3 bucket setup, to configure it with Trellix EDR Cloud, follow the steps mentioned below:
   - Login to your Trellix Admin Account, select Trellix ePO.
   - Go to Policy Catalog -> Trellix EDR.
   - Create a new policy by filling the required details and  click OK.
   - After creating a policy, click on edit for the policy you  want to edit.
   - Go to the Trace, fill in the details of the trace scanner and AWS S3 settings, and click on save.
   - Now go to the system tree and click on the system to which you want to assign the policy.
   - Go to Actions -> Agent -> Set Policy and Inheritance
   - Select the product under policy as MVISION EDR, and select the policy that you want to assign to this system, and click  save.
   - Policy is assigned to the system, and the system trace  logs will be sent to the AWS S3 bucket.
2. The default value of the field `Bucket List Prefix` is event/.

### To collect data from AWS SQS, follow the below steps:

1. Assuming you've already set up a connection to push data into the AWS bucket; if not, see the section above.
2. To set up an SQS queue, follow "Step 1: Create an Amazon SQS Queue" mentioned in the [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
   - While creating an access policy, use the bucket name configured to create a connection for AWS S3 in Trellix EDR Cloud.
3. Configure event notifications for an S3 bucket. Follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
   - While creating `event notification` select the event type as s3:ObjectCreated:*, destination type SQS Queue, and select the queue name created in Step 2.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type Trellix EDR Cloud
3. Click on the "Trellix EDR Cloud" integration from the search results.
4. Click on the Add Trellix EDR Cloud Integration button to add the integration.
5. While adding the integration, if you want to collect logs via AWS S3, then you have to put the following details:
   - access key id
   - secret access key
   - bucket arn
   - collect logs via S3 Bucket toggled on

   or if you want to collect logs via AWS SQS, then you have to put the following details:
   - access key id
   - secret access key
   - queue url
   - region
   - collect logs via S3 Bucket toggled off

**NOTE**: There are other input combination options available, please check [here](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html).

## Logs reference

### Event

This is the `Event` dataset.

#### Example

{{event "event"}}

{{fields "event"}}
