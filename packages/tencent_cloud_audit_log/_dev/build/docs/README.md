# tencent_cloud_audit_log Integration

## Overview

Explain what the integration is, define the third-party product that is providing data, establish its relationship to the larger ecosystem of Elastic products, and help the reader understand how it can be used to solve a tangible problem.
Check the [overview guidelines](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-overview) for more information.

## Datastreams


### tencent_cloud_audit_log

tencent cloud audit log


## Requirements

Elastic Agent must be installed. For more information, refer to [these instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

#### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

#### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrading of your agents considerably easier.

#### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

#### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

The requirements section helps readers to confirm that the integration will work with their systems.
Check the [requirements guidelines](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-requirements) for more information.

## Setup

Point the reader to the [Observability Getting started guide](https://www.elastic.co/guide/en/observability/master/observability-get-started.html) for generic, step-by-step instructions. Include any additional setup instructions beyond what’s included in the guide, which may include instructions to update the configuration of a third-party service.
Check the [setup guidelines](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-setup) for more information.

### Enabling the integration in Elastic:

#### Create a new integration from a ZIP file (optional)
1. In Kibana, go to **Management** > **Integrations**.
2. Select **Create new integration**.
3. Select **Upload it as a .zip**.
4. Upload the ZIP file.
5. Select **Add to Elastic**.

### Install the integration
1. In Kibana, go to **Management** > **Integrations**.
2. In **Search for integrations** search bar, type tencent_cloud_audit_log.
3. Click the **tencent_cloud_audit_log** integration from the search results.
4. Click the **Add tencent_cloud_audit_log** button to add the integration.
5. Add all the required integration configuration parameters.
6. Click **Save and continue** to save the integration.


### Collecting logs from Amazon S3 bucket

When S3 bucket log collection is enabled, users can retrieve logs from S3 objects that are pointed to by S3 notification events read from an SQS queue, or by directly polling list of S3 objects in an S3 bucket. 

The use of SQS notification is preferred; polling list of S3 objects is expensive in terms of performance and costs and should be preferably used only when no SQS notification can be attached to the S3 buckets. This input integration also supports S3 notification from SNS to SQS.

The SQS notification method is enabled setting `queue_url` configuration value. The S3 bucket list polling method is enabled setting `bucket_arn` configuration value and `number_of_workers` value. Exactly one of the `queue_url` and `bucket_arn` configuration options must be set.

#### To collect data from AWS SQS, follow the below steps:
1. If data forwarding to an AWS S3 Bucket hasn't been configured, then first setup an AWS S3 Bucket as mentioned in the above documentation.
2. Follow the steps below for each data stream that has been enabled:
     1. Create an SQS queue
         - To setup an SQS queue, follow "Step 1: Create an Amazon SQS queue" mentioned in the [Amazon documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
         - While creating an SQS Queue, please provide the same bucket ARN that has been generated after creating an AWS S3 Bucket.
     2. Setup event notification from the S3 bucket using the instructions [here](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html). Use the following settings:
        - Event type: `All object create events` (`s3:ObjectCreated:*`)
         - Destination: SQS Queue
         - Prefix (filter): enter the prefix for this data stream, e.g. `alert_logs/`
         - Select the SQS queue that has been created for this data stream

**Note**:
  - A separate SQS queue and S3 bucket notification is required for each enabled data stream.
  - Permissions for the above AWS S3 bucket and SQS queues should be configured according to the [Filebeat S3 input documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html#_aws_permissions_2)
  - Data collection via AWS S3 Bucket and AWS SQS are mutually exclusive in this case.




### TLS/SSL Configuration (Optional)
To enhance security, configure the server with TLS/SSL settings. This ensures secure communication between clients and the server. Below is an example of how to configure these settings:

```yml
ssl.certificate: "/etc/pki/server/cert.pem"
ssl.key: "/etc/pki/server/cert.key"
```

ssl.key: The private key used by the server to decrypt data encrypted with its corresponding public key, as well as to sign data to authenticate its identity.
ssl.certificate: The server's certificate, used to verify its identity. It contains the public key and is validated against a Certificate Authority (CA) to establish an encrypted connection with clients.

In the input settings, include any relevant SSL Configuration and Secret Header values depending on the specific requirements of your endpoint. You may also configure additional options such as certificate, keys, supported_protocols, and verification_mode. Refer to the [Elastic SSL Documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-server-config) for further details.



## Troubleshooting (optional)

- If some fields appear conflicted under the ``logs-*`` or ``metrics-*`` data views, this issue can be resolved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream) the impacted data stream.

Provide information about special cases and exceptions that aren’t necessary for getting started or won’t be applicable to all users. Check the [troubleshooting guidelines](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-troubleshooting) for more information.





## Reference

Provide detailed information about the log or metric types we support within the integration. Check the [reference guidelines](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-reference) for more information.

## Logs

### tencent_cloud_audit_log

tencent cloud audit log


{{fields "tencent_cloud_audit_log"}}
