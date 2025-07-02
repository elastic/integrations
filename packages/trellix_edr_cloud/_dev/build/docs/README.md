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

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

The minimum **kibana.version** required is **8.9.0**.

## Setup

### Collect data from an AWS S3 bucket

If you already have an AWS S3 bucket setup, configure it with Trellix EDR Cloud by following these steps:

1. Login to your Trellix Admin Account, select Trellix ePO.
2. Go to Policy Catalog -> Trellix EDR.
3. Create a new policy by filling the required details and  click OK.
4. After creating a policy, click on edit for the policy you  want to edit.
5. Go to the Trace, fill in the details of the trace scanner and AWS S3 settings, and click on save.
6. Now go to the system tree and click on the system to which you want to assign the policy.
7. Go to Actions -> Agent -> Set Policy and Inheritance
8. Select the product under policy as MVISION EDR, and select the policy that you want to assign to this system, and click  save.
9. Policy is assigned to the system, and the system trace  logs will be sent to the AWS S3 bucket.

The default value of the field `Bucket List Prefix` is event/.

### Collect data from AWS SQS

1. Assuming you've already set up a connection to push data into the AWS bucket; if not, see the section above.
2. To set up an SQS queue, follow "Step 1: Create an Amazon SQS Queue" as described in the [AWS documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
   - While creating an access policy, use the bucket name configured to create a connection for AWS S3 in Trellix EDR Cloud.
3. To configure event notifications for an S3 bucket refer to the [AWS documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
   - While creating `event notification` select the event type as `s3:ObjectCreated:*`, destination type SQS Queue, and select the queue name created in Step 2.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **Trellix EDR Cloud**.
3. Select the **Trellix EDR Cloud** integration and add it.
4. While adding the integration, if you want to collect logs via AWS S3, enter the following details:
   - access key id
   - secret access key
   - bucket arn or access point arn
   - collect logs via S3 Bucket toggled on

   or if you want to collect logs via AWS SQS, then you have to put the following details:
   - access key id
   - secret access key
   - queue url
   - region
   - collect logs via S3 Bucket toggled off
5. Save the integration. 

**NOTE**: For more input combination options, check the [AWS documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html).

## Logs reference

### Event

This is the `Event` dataset.

#### Example

{{event "event"}}

{{fields "event"}}
