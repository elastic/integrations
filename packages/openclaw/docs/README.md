# OpenClaw Integration

The OpenClaw integration allows you to ingest and monitor LLM observability metrics, session logs, and assistant usage data from the OpenClaw AI agent framework.

It provides a comprehensive view of:
- **Token Consumption**: Input and output tokens used per request.
- **Cost Analysis**: Financial cost incurred per model and session.
- **Tool Usage**: Which tools (skills) were executed and their frequencies.
- **Latency**: End-to-end response time of the AI agent.

## Data Streams

This integration includes the following data streams:

### Sessions Data Stream (`sessions`)

The `sessions` data stream collects detailed, turn-by-turn interactions from OpenClaw, capturing user prompts, agent thoughts, final responses, and internal metadata (like model versions and token counts).

**Exported Fields**

For a detailed list of exported fields, refer to the [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) and the specific fields listed below:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| openclaw.agent.id | Agent ID | keyword |
| openclaw.cost.usd | Cost in USD | float |
| openclaw.model | Model name | keyword |
| openclaw.role | Role of the message sender (user or assistant) | keyword |
| openclaw.session.id | Session ID | keyword |
| openclaw.text | Text content of the interaction | keyword |
| openclaw.thinking | Internal thinking process | keyword |
| openclaw.tool_calls.arguments | Arguments passed to the tool | flattened |
| openclaw.tool_calls.name | Name of the tool called | keyword |
| openclaw.usage.input_tokens | Number of input tokens | long |
| openclaw.usage.output_tokens | Number of output tokens | long |
| openclaw.usage.total_tokens | Total token usage | long |

