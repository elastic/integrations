# Amazon Bedrock

## Overview

[Amazon Bedrock](https://docs.aws.amazon.com/bedrock/index.html) is a fully managed AWS service that gives access to foundation models from Amazon and other AI companies through a single API.

The Amazon Bedrock integration collects model invocation logs, runtime metrics and guardrail metrics. Elastic Security can use this data for security analytics, including correlation, visualization and incident response. With invocation logging, you can collect the full request and response of every model call, and the metadata of the call.

**IMPORTANT: This integration makes AWS API requests, which AWS charges for. Check [API Requests](https://www.elastic.co/docs/current/integrations/aws#api-requests) for details.**

### Compatibility

This integration is compatible with the Amazon Bedrock `ModelInvocationLog` schema, version 1.0.

## What data does this integration collect?

Data streams:
 - `invocation`: invocation logs, with the model input and output, for every model call in your AWS account.
 - `runtime`: runtime metrics, such as invocation count, latency, token counts and throttled invocations.
 - `guardrails`: guardrail metrics, such as guardrail invocation count, latency, text units used and interventions by policy type.

## What do I need to use this integration?

You need Elasticsearch to store and search your data, and Kibana to view and manage it. You can use Elastic Cloud, which is recommended, or run the Elastic Stack on your own hardware.

You also need:

* **AWS credentials** to connect to your AWS account.
* **AWS permissions** for the user or role that connects, so that it can read the data.

For details, check the [AWS integration documentation](https://docs.elastic.co/integrations/aws#requirements).

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For details, check the Elastic Agent [installation instructions](https://www.elastic.co/docs/reference/fleet/install-elastic-agents). You can install only one Elastic Agent per host.

Elastic Agent collects the data from AWS and sends it to Elastic, where the integration's ingest pipelines process it.

### Elastic Managed deployment

Elastic Managed integrations collect data without an Elastic Agent that you deploy and manage yourself. For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations).

Elastic Managed deployments are only supported in Elastic Serverless and Elastic Cloud. This feature is in beta and is subject to change. Beta features are not covered by the support SLA of GA features.

Collecting logs from an S3 bucket requires an agent-based deployment.

## Setup

### Enable model invocation logging

The `invocation` data stream needs Amazon Bedrock model invocation logging, sent to S3 or CloudWatch Logs. An account administrator turns it on for each AWS account and Region. For details, check the [Amazon Bedrock User Guide](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html).

1. Set up an [Amazon S3](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html#setup-s3-destination) or [CloudWatch Logs](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html#setup-cloudwatch-logs-destination) destination.
2. Enable logging, in the [Amazon Bedrock console](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html#model-invocation-logging-console) or with [the Amazon Bedrock API](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html#using-apis-logging).
3. Choose the data types to log, and include at least text. Without data delivery, the logs only hold metadata: the model, the caller, token counts and errors, but no prompts or responses.

**Sensitive data.** With data delivery enabled, the logs hold the full prompts and responses of every model call, which can include personal or confidential data. Restrict access to the `invocation` data stream.

### Collect the logs from S3

The integration reads S3 objects either from S3 notification events received through an SQS queue, or by polling the bucket. SQS notifications are preferred, because polling costs more and is slower. S3 notifications sent through SNS to SQS also work.

- For SQS notifications, set `queue_url`.
- For polling, set `bucket_arn` and `number_of_workers`.

Set one of `queue_url` and `bucket_arn`, not both.

Bedrock writes request and response bodies over 100 KB, and binary data such as images, as separate objects under the `data/` prefix of the bucket. When the whole bucket is read, these objects are also ingested as documents of their own, and `aws_bedrock.invocation.request_id` links them to their log record. To skip them, set **File Selectors** to a regex that only matches the log files, for example:

```yaml
- regex: '/[0-9]{2}/[^/]+\.json\.gz$'
```

### Collect the logs from CloudWatch

The integration reads the log events of all log streams in the log group you set, with the `FilterLogEvents` API. With a CloudWatch Logs destination, bodies over 100 KB are only kept if a large-data S3 location (`largeDataDeliveryS3Config`) is set in the Bedrock logging configuration.

## GenAI fields

The `invocation` data stream maps each model call to the ECS `gen_ai.*` fields, such as `gen_ai.operation.name`, `gen_ai.usage.input_tokens`, `gen_ai.tool.name` and `gen_ai.response.finish_reasons`. The `runtime` and `guardrails` data streams set `gen_ai.provider.name` to `aws.bedrock`, and `runtime` also sets the model and token counts.

- `gen_ai.usage.input_tokens` includes cached input tokens.
- For the requested model, use `aws_bedrock.invocation.model_id`. `gen_ai.request.model` is not set yet.

**Deprecated fields.** Earlier versions wrote some `gen_ai.*` fields that are not part of ECS. They are still written, but will be removed in the next major version. Update your detection rules and dashboards to use the replacements:

| Deprecated field | Replacement |
|---|---|
| `gen_ai.request.model.id` | `aws_bedrock.invocation.model_id` |
| `gen_ai.system` | `gen_ai.provider.name` |
| `gen_ai.usage.prompt_tokens` | `gen_ai.usage.input_tokens` (includes cached tokens) |
| `gen_ai.usage.completion_tokens` | `gen_ai.usage.output_tokens` |
| `gen_ai.guardrail_id` | `aws_bedrock.invocation.guardrail.id` |
| `gen_ai.policy.*` | `aws_bedrock.invocation.guardrail.policy.*` |
| `gen_ai.compliance.*` | `aws_bedrock.invocation.guardrail.compliance.*` |
| `gen_ai.response.error_code` | `error.code` |
| `gen_ai.performance.response_time` | `event.duration` (nanoseconds) |
| `gen_ai.performance.start_response_time` | `aws_bedrock.invocation.first_byte_latency` |
| `gen_ai.user.id` | `user.id` |

In the next major version, `gen_ai.prompt` and `gen_ai.completion` also move, to `aws_bedrock.invocation.input.body_text` and `aws_bedrock.invocation.output.body_text`.

## Troubleshooting

- **No prompts or responses in the `invocation` data stream.** Data delivery for that data type is off in the Bedrock logging configuration. See [Enable model invocation logging](#enable-model-invocation-logging).
- **`gen_ai.prompt` or `gen_ai.completion` is missing on some documents.** Values longer than 32766 characters are removed. These documents carry the `gen_ai_prompt_removed` or `gen_ai_completion_removed` tag. A `completion_text` cut to that length carries the `completion_text_truncated` tag.
- **No reasoning text in the responses.** The application that calls Bedrock must ask for it. For Anthropic Claude, set `thinking` (with adaptive thinking, also `thinking.display: "summarized"`). For Amazon Nova, set `reasoningConfig`.
- **Token totals from `runtime` look doubled.** Bedrock publishes each metric per model, as an account total, and per model again split by context window or image settings. `gen_ai.usage.*` is only set on the per-model rows, so sum that field rather than the raw metrics.

## Reference

### Logs

{{fields "invocation"}}

### Runtime metrics

The runtime metrics are `Invocations`, `InvocationLatency`, `InvocationClientErrors`, `InvocationServerErrors`, `InvocationThrottles`, `LegacyModelInvocations`, `InputTokenCount`, `CacheReadInputTokenCount`, `CacheWriteInputTokenCount`, `OutputTokenCount` and `OutputImageCount`.

{{event "runtime"}}
{{fields "runtime"}}

### Guardrails metrics

The guardrail metrics are `Invocations`, `InvocationLatency`, `InvocationClientErrors`, `InvocationServerErrors`, `InvocationThrottles`, `TextUnitCount` and `InvocationsIntervened`.

{{event "guardrails"}}
{{fields "guardrails"}}
