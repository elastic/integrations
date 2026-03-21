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

For a detailed list of exported fields, please see the [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) and the specific fields listed below:

{{fields "sessions"}}
