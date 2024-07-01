# AWS Bedrock model invocation logs

The [AWS Bedrock](https://docs.aws.amazon.com/bedrock/index.html) model
invocation logs integration allows you to easily connect your Bedrock model
invocation logging to Elastic for seamless collection of invocation logs to
monitor usage. Elastic Security can leverage this data for security analytics
including correlation, visualization and incident response. With invocation
logging, you can collect the full request and response data, and any metadata
associated with use of your account.


## Compatibility

This integration is compatible with the AWS Bedrock ModelInvocationLog schema,
version 1.0.


## Data streams

The AWS Bedrock model invocation logs integration currently provides a single
data stream of model invocation logs, `aws_bedrock.invocation`.


## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data from the S3 bucket and ship the
  data to Elastic, where the events will then be processed via the
  integration's ingest pipelines.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to
define, configure, and manage your agents in a central location. We recommend
using Fleet management because it makes the management and upgrade of your
agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent
locally on the system where it is installed. You are responsible for managing
and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or
standalone. Docker images for all versions of Elastic Agent are available
from the Elastic Docker registry, and we provide deployment manifests for
running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more
information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.12.0**.


### Setup

In order to use the AWS Bedrock model invocation logs, logging model
invocation logging must be enabled and be sent to a log store destination,
either S3 or CloudWatch. The full details of this are available from the
[AWS Bedrock User Guide](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html),
but outlined here.

1. Set up an [Amazon S3](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html#setup-s3-destination) or [CloudWatch](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html#setup-cloudwatch-logs-destination) Logs destination.
2. Enable logging. This can be done either through the [AWS Bedrock console](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html#model-invocation-logging-console) or [the AWS Bedrock API](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html#using-apis-logging). 


## Collecting Bedrock model invocation logs from S3 bucket

When collecting logs from S3 bucket is enabled, users can retrieve logs from S3
objects that are pointed to by S3 notification events read from an SQS queue or
directly polling list of S3 objects in an S3 bucket. 

The use of SQS notification is preferred: polling list of S3 objects is 
expensive in terms of performance and costs and should be preferably used only 
when no SQS notification can be attached to the S3 buckets. This input 
integration also supports S3 notification from SNS to SQS.

SQS notification method is enabled setting `queue_url` configuration value. S3 
bucket list polling method is enabled setting `bucket_arn` configuration value
and `number_of_workers` value. Both `queue_url` and `bucket_arn` cannot be set 
at the same time and at least one of the two value must be set.

## Collecting Bedrock model invocation logs from CloudWatch

When collecting logs from CloudWatch is enabled, users can retrieve logs from 
all log streams in a specific log group. `filterLogEvents` AWS API is used to 
list log events from the specified log group.

{{fields "invocation"}}
