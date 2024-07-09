# AWS Health

AWS Health metrics provide insights into the health of your AWS environment by monitoring various aspects such as open issues, scheduled maintenance events, security advisories, compliance status, notification counts, and service disruptions. These metrics help you proactively identify and address issues impacting your AWS resources, ensuring the reliability, security, and compliance of your infrastructure.

## Data streams

The AWS Health integration collects one type of data: metrics.

Metrics provide insight into the operational health of your AWS environment, including the status of AWS services, scheduled changes, and notifications about potential issues that could impact your resources. Metrics are gathered with the [AWS Health API](https://docs.aws.amazon.com/health/latest/APIReference/Welcome.html)

See more details in the [Metrics reference](#metrics-reference).


## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, please take a look at the [AWS integration documentation](https://docs.elastic.co/integrations/aws#requirements).

To collect AWS Health metrics, you would need specific AWS permissions to access the necessary data. Here's a list of permissions required for an IAM user to collect AWS Health metrics:

- `health:DescribeAffectedEntities`
- `health:DescribeEventDetails`
- `health:DescribeEvents`


## Setup

If you want to collect data from two or more AWS services, consider using the **AWS** integration. When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
{{ url "getting-started-observability" "Getting started" }} guide.

### Data stream specific configuration notes

`Period`:: (_string_) Reporting interval. Recommended value is `24h`.

## Metrics reference

The `awshealth` data stream collects AWS Health metrics from AWS.

An example event for `awshealth` looks as following:

{{event "awshealth"}}

{{fields "awshealth"}}