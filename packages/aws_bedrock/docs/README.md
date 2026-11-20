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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| aws.cloudwatch.message | CloudWatch log message. | text |
| aws.s3.bucket.arn | ARN of the S3 bucket that this log retrieved from. | keyword |
| aws.s3.bucket.name | Name of the S3 bucket that this log retrieved from. | keyword |
| aws.s3.object.key | Name of the S3 object that this log retrieved from. | keyword |
| aws_bedrock.invocation.artifacts |  | flattened |
| aws_bedrock.invocation.error |  | keyword |
| aws_bedrock.invocation.error_code |  | keyword |
| aws_bedrock.invocation.first_byte_latency | Time to the first byte of a streamed response, in milliseconds (amazon-bedrock-invocationMetrics.firstByteLatency). | long |
| aws_bedrock.invocation.guardrail.arn | Guardrail ARNs, from the request guardrailConfig or the trace appliedGuardrailDetails. | keyword |
| aws_bedrock.invocation.guardrail.compliance.violation_code | Code identifying the specific compliance rule that was violated. | keyword |
| aws_bedrock.invocation.guardrail.compliance.violation_detected | Indicates if any compliance violation was detected during the interaction. | boolean |
| aws_bedrock.invocation.guardrail.id | Guardrail IDs that assessed the invocation. | keyword |
| aws_bedrock.invocation.guardrail.policy.action | Action taken due to a policy violation, such as blocking, alerting, or modifying the content. | keyword |
| aws_bedrock.invocation.guardrail.policy.confidence | Confidence level in the policy match that triggered the action, quantifying how closely the identified content matched the policy criteria. | keyword |
| aws_bedrock.invocation.guardrail.policy.match_detail.\* |  | object |
| aws_bedrock.invocation.guardrail.policy.match_detail.score |  | float |
| aws_bedrock.invocation.guardrail.policy.match_detail.threshold |  | float |
| aws_bedrock.invocation.guardrail.policy.name | Name of the specific policy that was triggered. | keyword |
| aws_bedrock.invocation.guardrail.version | Guardrail versions, from the request guardrailConfig or the trace appliedGuardrailDetails. | keyword |
| aws_bedrock.invocation.image_generation_config.cfg_scale |  | double |
| aws_bedrock.invocation.image_generation_config.height |  | long |
| aws_bedrock.invocation.image_generation_config.number_of_images |  | long |
| aws_bedrock.invocation.image_generation_config.quality |  | keyword |
| aws_bedrock.invocation.image_generation_config.seed |  | long |
| aws_bedrock.invocation.image_generation_config.width |  | long |
| aws_bedrock.invocation.image_variation_params.images |  | keyword |
| aws_bedrock.invocation.image_variation_params.text |  | keyword |
| aws_bedrock.invocation.images |  | keyword |
| aws_bedrock.invocation.input.input_body_json |  | flattened |
| aws_bedrock.invocation.input.input_body_json_massive_hash |  | keyword |
| aws_bedrock.invocation.input.input_body_json_massive_length |  | long |
| aws_bedrock.invocation.input.input_body_s3_path |  | keyword |
| aws_bedrock.invocation.input.input_content_type |  | keyword |
| aws_bedrock.invocation.input.input_token_count | The number of tokens used in the GenAI input. | long |
| aws_bedrock.invocation.input.messages_content_kinds | The different content formats related to the input messages/prompts. | keyword |
| aws_bedrock.invocation.max_tokens | Maximum number of tokens to generate, from the root of an S3 data-prefix request body object that was ingested without its invocation log record. | long |
| aws_bedrock.invocation.messages.content.text |  | match_only_text |
| aws_bedrock.invocation.messages.content.type |  | keyword |
| aws_bedrock.invocation.messages.role |  | keyword |
| aws_bedrock.invocation.model_id |  | keyword |
| aws_bedrock.invocation.output.completion_text | The formatted LLM text model responses. Only a limited number of LLM text models are supported. | text |
| aws_bedrock.invocation.output.output_body_json |  | flattened |
| aws_bedrock.invocation.output.output_body_json_massive_hash |  | keyword |
| aws_bedrock.invocation.output.output_body_s3_path |  | keyword |
| aws_bedrock.invocation.output.output_content_type |  | keyword |
| aws_bedrock.invocation.output.output_token_count |  | long |
| aws_bedrock.invocation.output.stop_details.category | Category of a refusal stop (Anthropic stop_details.category). | keyword |
| aws_bedrock.invocation.performance_config.latency | Latency mode of the request (Converse performanceConfig.latency). | keyword |
| aws_bedrock.invocation.request.reasoning_budget_tokens | Token budget for extended thinking (Anthropic thinking.budget_tokens). | long |
| aws_bedrock.invocation.request.reasoning_display | Requested display of the thinking content (Anthropic thinking.display). | keyword |
| aws_bedrock.invocation.request.reasoning_effort | Requested reasoning effort (Anthropic output_config.effort, Nova reasoningConfig.maxReasoningEffort, OpenAI reasoning_effort). | keyword |
| aws_bedrock.invocation.request.reasoning_type | Requested reasoning mode (Anthropic thinking.type, Nova reasoningConfig.type). | keyword |
| aws_bedrock.invocation.requestMetadata.\* | Caller request tags (envelope requestMetadata), as they arrive. A copy is in aws_bedrock.invocation.request_metadata. | object |
| aws_bedrock.invocation.request_id |  | keyword |
| aws_bedrock.invocation.request_metadata | Caller request tags (envelope requestMetadata). | flattened |
| aws_bedrock.invocation.result |  | keyword |
| aws_bedrock.invocation.schema_type |  | keyword |
| aws_bedrock.invocation.schema_version |  | keyword |
| aws_bedrock.invocation.service_tier | Service tier of the request (Converse serviceTier.type). | keyword |
| aws_bedrock.invocation.system.text |  | match_only_text |
| aws_bedrock.invocation.system.type |  | keyword |
| aws_bedrock.invocation.task_type |  | keyword |
| aws_bedrock.invocation.usage.cache_read_input_tokens | Input tokens read from the prompt cache (Converse cacheReadInputTokens, Anthropic cache_read_input_tokens, OpenAI prompt_tokens_details.cached_tokens). Included in gen_ai.usage.input_tokens. | long |
| aws_bedrock.invocation.usage.cache_write_input_tokens | Input tokens written to the prompt cache (Converse cacheWriteInputTokens, Anthropic cache_creation_input_tokens). Included in gen_ai.usage.input_tokens. | long |
| aws_bedrock.invocation.usage.reasoning_tokens | Reasoning tokens reported separately by OpenAI-format responses (completion_tokens_details.reasoning_tokens). Included in gen_ai.usage.output_tokens. | long |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| error.code | Error code describing the error. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If `event.start` and `event.end` are known this value should be the difference between the end and start time. | long |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| gen_ai.analysis.action_recommended | Recommended actions based on the analysis. | keyword |
| gen_ai.analysis.findings | Detailed findings from security tools. | nested |
| gen_ai.analysis.function | Name of the security or analysis function used. | keyword |
| gen_ai.analysis.tool_names | Name of the security or analysis tools used. | keyword |
| gen_ai.completion | The full text of the LLM's response. | text |
| gen_ai.compliance.request_triggered | Deprecated, with no replacement. Lists compliance-related filters that were triggered during the processing of the request, such as data privacy filters or regulatory compliance checks. | keyword |
| gen_ai.compliance.response_triggered | Deprecated, with no replacement. Lists compliance-related filters that were triggered during the processing of the response, such as data privacy filters or regulatory compliance checks. | keyword |
| gen_ai.compliance.violation_code | Deprecated, use `aws_bedrock.invocation.guardrail.compliance.violation_code` instead. Code identifying the specific compliance rule that was violated. | keyword |
| gen_ai.compliance.violation_detected | Deprecated, use `aws_bedrock.invocation.guardrail.compliance.violation_detected` instead. Indicates if any compliance violation was detected during the interaction. | boolean |
| gen_ai.guardrail_id | Deprecated, use `aws_bedrock.invocation.guardrail.id` instead. Guardrail ID if a guardrail was executed. | keyword |
| gen_ai.input.messages | The chat history provided to the model as an input. | flattened |
| gen_ai.operation.name | The name of the operation being performed. | keyword |
| gen_ai.output.messages | Messages returned by the model where each message represents a specific model response (choice, candidate). | flattened |
| gen_ai.output.type | Represents the content type requested by the client. | keyword |
| gen_ai.owasp.description | Description of the OWASP risk triggered. | text |
| gen_ai.owasp.id | Identifier for the OWASP risk addressed. | keyword |
| gen_ai.performance.request_size | Size of the request payload in bytes. | long |
| gen_ai.performance.response_size | Size of the response payload in bytes. | long |
| gen_ai.performance.response_time | Deprecated, use `event.duration` (nanoseconds) instead. Time taken by the LLM to generate a response in milliseconds. | long |
| gen_ai.performance.start_response_time | Deprecated, use `aws_bedrock.invocation.first_byte_latency` instead. Time taken by the LLM to send first response byte in milliseconds. | long |
| gen_ai.policy.action | Deprecated, use `aws_bedrock.invocation.guardrail.policy.action` instead. Action taken due to a policy violation, such as blocking, alerting, or modifying the content. | keyword |
| gen_ai.policy.confidence | Deprecated, use `aws_bedrock.invocation.guardrail.policy.confidence` instead. Confidence level in the policy match that triggered the action, quantifying how closely the identified content matched the policy criteria. | keyword |
| gen_ai.policy.match_detail.\* |  | object |
| gen_ai.policy.match_detail.score |  | float |
| gen_ai.policy.match_detail.threshold |  | float |
| gen_ai.policy.name | Deprecated, use `aws_bedrock.invocation.guardrail.policy.name` instead. Name of the specific policy that was triggered. | keyword |
| gen_ai.policy.violation | Deprecated, with no replacement. Specifies if a security policy was violated. | boolean |
| gen_ai.prompt | The full text of the user's request to the gen_ai. | text |
| gen_ai.provider.name | The Generative AI provider as identified by the client or server instrumentation. | constant_keyword |
| gen_ai.request.choice.count | The target number of candidate completions to return. | long |
| gen_ai.request.encoding_formats | Encoding formats requested in an embeddings operation. Defined locally as keyword because ECS types it as nested without properties (elastic/ecs#2560). | keyword |
| gen_ai.request.frequency_penalty | The frequency penalty setting for the GenAI request. | double |
| gen_ai.request.id | Unique identifier for the LLM request. | keyword |
| gen_ai.request.max_tokens | The maximum number of tokens the model generates for a request. | long |
| gen_ai.request.model.description | Description of the LLM model. | keyword |
| gen_ai.request.model.id | Deprecated, use `aws_bedrock.invocation.model_id` instead. Unique identifier for the LLM model. | keyword |
| gen_ai.request.model.instructions | Custom instructions for the LLM model. | text |
| gen_ai.request.model.role | Role of the LLM model in the interaction. | keyword |
| gen_ai.request.model.type | Type of LLM model. | keyword |
| gen_ai.request.model.version | Version of the LLM model used to generate the response. | keyword |
| gen_ai.request.presence_penalty | The presence penalty setting for the GenAI request. | double |
| gen_ai.request.seed | Requests with same seed value more likely to return same result. | long |
| gen_ai.request.stop_sequences | List of sequences that the model will use to stop generating further tokens. Defined locally as keyword because ECS types it as nested without properties (elastic/ecs#2560). | keyword |
| gen_ai.request.temperature | The temperature setting for the GenAI request. | double |
| gen_ai.request.timestamp | Timestamp when the request was made. | date |
| gen_ai.request.top_k | The top_k sampling setting for the GenAI request. | double |
| gen_ai.request.top_p | The top_p sampling setting for the GenAI request. | double |
| gen_ai.response.error_code | Deprecated, use `error.code` instead. Error code returned in the LLM response. | keyword |
| gen_ai.response.finish_reasons | Reason the LLM response stopped. | keyword |
| gen_ai.response.id | The unique identifier for the completion. | keyword |
| gen_ai.response.model | The name of the model that generated the response. | keyword |
| gen_ai.response.timestamp | Timestamp when the response was received. | date |
| gen_ai.security.hallucination_consistency | Consistency check between multiple responses. | float |
| gen_ai.security.jailbreak_score | Measures similarity to known jailbreak attempts. | float |
| gen_ai.security.prompt_injection_score | Measures similarity to known prompt injection attacks. | float |
| gen_ai.security.refusal_score | Measures similarity to known LLM refusal responses. | float |
| gen_ai.security.regex_pattern_count | Counts occurrences of strings matching user-defined regex patterns. | integer |
| gen_ai.sentiment.content_categories | Categories of content identified as sensitive or requiring moderation. | keyword |
| gen_ai.sentiment.content_inappropriate | Whether the content was flagged as inappropriate or sensitive. | boolean |
| gen_ai.sentiment.score | Sentiment analysis score. | float |
| gen_ai.sentiment.toxicity_score | Toxicity analysis score. | float |
| gen_ai.system | Deprecated, use `gen_ai.provider.name` instead. Name of the LLM foundation model vendor. | keyword |
| gen_ai.system_instructions | The system message or instructions provided to the GenAI model separately from the chat history. | flattened |
| gen_ai.text.complexity_score | Evaluates the complexity of the text. | float |
| gen_ai.text.readability_score | Measures the readability level of the text. | float |
| gen_ai.text.similarity_score | Measures the similarity between the prompt and response. | float |
| gen_ai.threat.action | Recommended action to mitigate the detected security threat. | keyword |
| gen_ai.threat.category | Category of the detected security threat. | keyword |
| gen_ai.threat.description | Description of the detected security threat. | text |
| gen_ai.threat.detected | Whether a security threat was detected. | boolean |
| gen_ai.threat.risk_score | Numerical score indicating the potential risk associated with the response. | float |
| gen_ai.threat.signature | Signature of the detected security threat. | keyword |
| gen_ai.threat.source | Source of the detected security threat. | keyword |
| gen_ai.threat.type | Type of threat detected in the LLM interaction. | keyword |
| gen_ai.threat.yara_matches | Stores results from YARA scans including rule matches and categories. | nested |
| gen_ai.tool.call.id | The tool call identifier. | keyword |
| gen_ai.tool.definitions | The list of source system tool definitions available to the GenAI agent or model. | flattened |
| gen_ai.tool.name | Name of the tool utilized by the agent. | keyword |
| gen_ai.tool.type | Type of the tool utilized by the agent | keyword |
| gen_ai.usage.completion_tokens | Deprecated, use `gen_ai.usage.output_tokens` instead. Number of tokens in the LLM's response. | integer |
| gen_ai.usage.input_tokens | The number of tokens used in the GenAI input (prompt). | long |
| gen_ai.usage.output_tokens | The number of tokens used in the GenAI response (completion). | long |
| gen_ai.usage.prompt_tokens | Deprecated, use `gen_ai.usage.input_tokens` instead. Number of tokens in the user's request. | integer |
| gen_ai.user.id | Deprecated, use `user.id` instead. Unique identifier for the user. | keyword |
| gen_ai.user.rn | Unique resource name for the user. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset | long |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| user.email | User email address. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |


### Runtime metrics

The runtime metrics are `Invocations`, `InvocationLatency`, `InvocationClientErrors`, `InvocationServerErrors`, `InvocationThrottles`, `LegacyModelInvocations`, `InputTokenCount`, `CacheReadInputTokenCount`, `CacheWriteInputTokenCount`, `OutputTokenCount` and `OutputImageCount`.

An example event for `runtime` looks as following:

```json
{
    "@timestamp": "2024-07-15T07:35:00.000Z",
    "agent": {
        "ephemeral_id": "63673811-d18c-4209-8818-df8b346bcb28",
        "id": "47a2173f-3f59-4a7c-a022-dee86802c2c1",
        "name": "service-integration-dev-idc-1",
        "type": "metricbeat",
        "version": "8.13.4"
    },
    "aws": {
        "cloudwatch": {
            "namespace": "AWS/Bedrock"
        }
    },
    "aws_bedrock": {
        "runtime": {
            "input_token_count": 848,
            "invocation_latency": 2757,
            "invocations": 5,
            "output_token_count": 1775
        }
    },
    "cloud": {
        "account": {
            "id": "00000000000000",
            "name": "MonitoringAccount"
        },
        "provider": "aws",
        "region": "ap-south-1"
    },
    "data_stream": {
        "dataset": "aws_bedrock.runtime",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "47a2173f-3f59-4a7c-a022-dee86802c2c1",
        "snapshot": false,
        "version": "8.13.4"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "aws_bedrock.runtime",
        "duration": 174434808,
        "ingested": "2024-07-15T07:44:02Z",
        "module": "aws"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "service-integration-dev-idc-1",
        "id": "1bfc9b2d8959f75a520a3cb94cf035c8",
        "ip": [
            "10.160.0.4",
            "172.1.0.1",
            "172.17.0.1",
            "172.19.0.1",
            "172.20.0.1",
            "172.22.0.1",
            "172.23.0.1",
            "172.26.0.1",
            "172.27.0.1",
            "172.28.0.1",
            "172.29.0.1",
            "172.30.0.1",
            "172.31.0.1",
            "192.168.0.1",
            "192.168.32.1",
            "192.168.49.1",
            "192.168.80.1",
            "192.168.224.1",
            "fe80::42:9cff:fe5b:79b4",
            "fe80::42:a5ff:fe15:d63c",
            "fe80::42:beff:fe39:f457",
            "fe80::42a:f7ff:fe6c:421d",
            "fe80::1818:53ff:fea8:3f38",
            "fe80::4001:aff:fea0:4",
            "fe80::8cfa:3aff:fedb:656a",
            "fe80::c890:29ff:fe99:ac1b",
            "fe80::fcfc:c2ff:feca:1e28"
        ],
        "mac": [
            "02-42-0D-A6-43-C0",
            "02-42-23-32-CF-25",
            "02-42-27-90-E6-54",
            "02-42-34-10-CA-62",
            "02-42-4F-1D-94-1B",
            "02-42-50-2E-CB-58",
            "02-42-5D-42-F3-1D",
            "02-42-66-9B-25-B2",
            "02-42-99-B7-1B-26",
            "02-42-9C-5B-79-B4",
            "02-42-A5-15-D6-3C",
            "02-42-A6-68-F8-E9",
            "02-42-BE-39-F4-57",
            "02-42-CE-31-B7-A3",
            "02-42-E8-F3-CF-7A",
            "02-42-F1-35-B0-41",
            "02-42-F4-2F-0F-22",
            "06-2A-F7-6C-42-1D",
            "1A-18-53-A8-3F-38",
            "42-01-0A-A0-00-04",
            "8E-FA-3A-DB-65-6A",
            "CA-90-29-99-AC-1B",
            "FE-FC-C2-CA-1E-28"
        ],
        "name": "service-integration-dev-idc-1",
        "os": {
            "codename": "bionic",
            "family": "debian",
            "kernel": "5.4.0-1106-gcp",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "18.04.6 LTS (Bionic Beaver)"
        }
    },
    "metricset": {
        "name": "cloudwatch",
        "period": 300000
    },
    "service": {
        "type": "aws"
    }
}
```
**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |  |
| aws.cloudwatch.namespace | The namespace specified when query cloudwatch api. | keyword |  |  |
| aws.dimensions.ContextWindow | The raw CloudWatch `ContextWindow` dimension. Rows that carry it are a subset of the per-model totals and get no `gen_ai.request.model` or `gen_ai.usage.\*`. | keyword |  |  |
| aws.metrics_names_fingerprint | Autogenerated ID representing the fingerprint of the list of metrics names. | keyword |  |  |
| aws_bedrock.runtime.bucketed_step_size |  | keyword |  |  |
| aws_bedrock.runtime.cache_read_input_token_count | The number of input tokens read from the prompt cache. Not included in `input_token_count`. | long |  | gauge |
| aws_bedrock.runtime.cache_write_input_token_count | The number of input tokens written to the prompt cache. Not included in `input_token_count`. | long |  | gauge |
| aws_bedrock.runtime.image_size |  | keyword |  |  |
| aws_bedrock.runtime.input_token_count | The number of text input tokens. | long |  | gauge |
| aws_bedrock.runtime.invocation_client_errors | The number of invocations that result in client-side errors. | long |  | gauge |
| aws_bedrock.runtime.invocation_latency | The average latency of the invocations. | long | ms | gauge |
| aws_bedrock.runtime.invocation_server_errors | The number of invocations that result in AWS server-side errors. | long |  | gauge |
| aws_bedrock.runtime.invocation_throttles | The number of invocations that the system throttled. | long |  | gauge |
| aws_bedrock.runtime.invocations | The number of requests to the `Converse`, `ConverseStream`, `InvokeModel`, and `InvokeModelWithResponseStream` API operations. | long |  | gauge |
| aws_bedrock.runtime.legacymodel_invocations | The number of requests to the legacy models. | long |  | gauge |
| aws_bedrock.runtime.model_id |  | keyword |  |  |
| aws_bedrock.runtime.output_image_count | The number of output images. | long |  | gauge |
| aws_bedrock.runtime.output_token_count | The number of text output tokens. | long |  | gauge |
| aws_bedrock.runtime.quality |  | keyword |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |  |  |
| gen_ai.provider.name | The Generative AI provider as identified by the client or server instrumentation. | constant_keyword |  |  |
| gen_ai.request.model | The name of the GenAI model a request is being made to. | keyword |  |  |
| gen_ai.usage.input_tokens | The number of tokens used in the GenAI input (prompt). | long |  | gauge |
| gen_ai.usage.output_tokens | The number of tokens used in the GenAI response (completion). | long |  | gauge |


### Guardrails metrics

The guardrail metrics are `Invocations`, `InvocationLatency`, `InvocationClientErrors`, `InvocationServerErrors`, `InvocationThrottles`, `TextUnitCount` and `InvocationsIntervened`.

An example event for `guardrails` looks as following:

```json
{
    "@timestamp": "2025-01-08T08:35:00.000Z",
    "agent": {
        "ephemeral_id": "457aa99d-9fdf-4494-9d06-31961a43f33a",
        "id": "9cdf7072-cfc1-4ad5-b68d-b51f0cd9afa8",
        "name": "elastic-agent-21656",
        "type": "metricbeat",
        "version": "8.16.2"
    },
    "aws": {
        "cloudwatch": {
            "namespace": "AWS/Bedrock/Guardrails"
        }
    },
    "aws_bedrock": {
        "guardrails": {
            "invocation_latency": 207,
            "invocations": 6,
            "invocations_intervened": 3,
            "operation": "ApplyGuardrail",
            "text_unit_count": 21
        }
    },
    "cloud": {
        "account": {
            "id": "11111111111111111",
            "name": "MonitoringAccount"
        },
        "provider": "aws",
        "region": "ap-south-1"
    },
    "data_stream": {
        "dataset": "aws_bedrock.guardrails",
        "namespace": "63909",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "9cdf7072-cfc1-4ad5-b68d-b51f0cd9afa8",
        "snapshot": false,
        "version": "8.16.2"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "aws_bedrock.guardrails",
        "duration": 100053062,
        "ingested": "2025-01-08T08:43:11Z",
        "module": "aws"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "elastic-agent-21656",
        "ip": [
            "172.26.0.5",
            "172.29.0.2"
        ],
        "mac": [
            "02-42-AC-1A-00-05",
            "02-42-AC-1D-00-02"
        ],
        "name": "elastic-agent-21656",
        "os": {
            "family": "",
            "kernel": "5.4.0-1106-gcp",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "metricset": {
        "name": "cloudwatch",
        "period": 300000
    },
    "service": {
        "type": "aws"
    }
}
```
**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |  |
| aws.cloudwatch.namespace | The namespace specified when query cloudwatch api. | keyword |  |  |
| aws.metrics_names_fingerprint | Autogenerated ID representing the fingerprint of the list of metrics names. | keyword |  |  |
| aws_bedrock.guardrails.guardrail_arn |  | keyword |  |  |
| aws_bedrock.guardrails.guardrail_content_source |  | keyword |  |  |
| aws_bedrock.guardrails.guardrail_policy_type |  | keyword |  |  |
| aws_bedrock.guardrails.guardrail_version |  | keyword |  |  |
| aws_bedrock.guardrails.invocation_client_errors | The number of invocations that result in AWS client-side errors. | long |  | gauge |
| aws_bedrock.guardrails.invocation_latency | The latency of the invocations. | long | ms | gauge |
| aws_bedrock.guardrails.invocation_server_errors | The number of invocations that result in AWS server-side errors. | long |  | gauge |
| aws_bedrock.guardrails.invocation_throttles | The number of invocations that the system throttled. | long |  | gauge |
| aws_bedrock.guardrails.invocations | The number of requests to the `ApplyGuardrail` API operation. | long |  | gauge |
| aws_bedrock.guardrails.invocations_intervened | The number of invocations where the guardrails intervened. | long |  | gauge |
| aws_bedrock.guardrails.operation |  | keyword |  |  |
| aws_bedrock.guardrails.text_unit_count | The number of text units consumed by the guardrails policies. | long |  | gauge |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| gen_ai.provider.name | The Generative AI provider as identified by the client or server instrumentation. | constant_keyword |  |  |

