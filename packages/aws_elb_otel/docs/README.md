# AWS ELB Logs with EDOT Cloud Forwarder

The AWS ELB logs integration allows you to monitor [AWS Elastic Load Balancer (ELB)](https://aws.amazon.com/elasticloadbalancing/), a service that automatically distributes incoming application traffic across multiple targets, such as EC2 instances, containers, and IP addresses.

The EDOT Cloud Forwarder for AWS enables you to collect **Application Load Balancer (ALB)** and **Network Load Balancer (NLB)** access logs from Amazon S3 and forward them directly into Elastic Observability. This integration provides a visual representation of ELB traffic and request data, enabling you to monitor performance, security, and troubleshoot issues in real time.

## Compatibility

The EDOT Cloud Forwarder for AWS supports collecting logs from:

* Application Load Balancers
* Network Load Balancers

For the full documentation on how to set up the EDOT Cloud Forwarder, follow this link: [EDOT Cloud Forwarder for AWS](https://www.elastic.co/docs/reference/opentelemetry/edot-cloud-forwarder/aws).

## Requirements

You need an Elastic Observability project (Serverless recommended) for storing, analyzing, and visualizing your ELB logs.
You can use the hosted Elasticsearch Service on Elastic Cloud, which is recommended.

Additionally:

* An S3 bucket must be configured as the destination for your ELB access logs.
* Permissions to deploy AWS CloudFormation stacks in your account.
* An Elastic **OTLP endpoint** and **API key** for authentication.

## Setup

1. Enable **Access Logs** for your Application Load Balancer (or Network Load Balancer), with an S3 bucket as the destination.

2. Deploy the **EDOT Cloud Forwarder for AWS** using Elastic’s provided **CloudFormation template** for ELB logs. You can do this via the AWS Console or AWS CLI. Example CLI command:

```bash
aws cloudformation create-stack \
  --stack-name edot-elb-forwarder \
  --template-url https://<elastic-cloudformation-template-for-elb>.yaml \
  --parameters \
    ParameterKey=S3BucketName,ParameterValue=<your-elb-log-bucket> \
    ParameterKey=ElasticOTLPEndpoint,ParameterValue=<your-otlp-endpoint> \
    ParameterKey=ElasticAPIKey,ParameterValue=<your-api-key>
```

3. Once the stack is created, it provisions:

   * A Lambda function (the forwarder),
   * IAM role and permissions,
   * Event notification on your S3 bucket to trigger the Lambda when new ELB logs arrive.

4. Generate some traffic on your ELB. Logs will flow to S3 → trigger the Lambda → forward to Elastic.

5. In **Discover**, verify that logs are arriving and fields such as `client.address`, `http.request.full`, `network.protocol.name` are populated.

## Logs reference

### AWS ELB logs

AWS ELB access logs provide detailed information about requests sent to your load balancer, including:

* Request start/stop times
* Client IP address
* Target IP address
* Request processing times
* HTTP method, URL, and protocol
* Target status code
* Bytes received/sent

Please refer to [the AWS documentation on ELB access logs](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html) for details on log format and fields.

For the full setup instructions and advanced configuration, see the [EDOT Cloud Forwarder for AWS documentation](https://www.elastic.co/docs/reference/opentelemetry/edot-cloud-forwarder/aws).