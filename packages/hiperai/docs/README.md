# HiperAI SecureAI

The HiperAI SecureAI integration collects security events, audit logs, AI governance violations, DLP alerts, and authentication activity from the [SecureAI](https://hiperai.com) enterprise AI security and governance platform.

## Overview

[HiperAI SecureAI](https://docs.hiperai.com) is an enterprise security, DLP, and governance platform for generative AI and LLM workflows. It provides:

- **Real-time AI usage monitoring** — Comprehensive audit logs for all LLM interactions
- **SMLTP policy enforcement** — Deterministic, cryptographically signed policy control for AI model access (Secure Model Link Transport Protocol)
- **Prompt injection detection** — Real-time detection and blocking of adversarial prompts
- **DLP for AI** — Sensitive data protection preventing PII, credentials, and confidential data from reaching AI models
- **Shadow AI discovery** — Detection of unauthorized AI tool usage across the enterprise

This integration enables SOC analysts and security teams to correlate AI-specific security events with traditional enterprise telemetry in Elastic Security.

## Compatibility

This integration has been tested with:
- SecureAI version 1.1.x and later
- Elastic Stack version 8.12.0 and later

## Setup

### Option A: Using Elastic Agent HTTP Endpoint (Recommended)

1. In Kibana, navigate to **Fleet** → **Integrations** → search for **HiperAI SecureAI**.
2. Click **Add HiperAI SecureAI** and configure the HTTP listener port (default: `8089`).
3. Deploy the agent policy to your Elastic Agent.
4. In the SecureAI admin console, navigate to **Integrations** → **Elastic SIEM**.
5. Configure the **Elastic URL** to point to the Elastic Agent HTTP endpoint:
   ```
   http://<agent-host>:8089
   ```
6. Set the **Elastic API Key** if you configured a secret header.
7. Select the **Event Categories** you want to forward.
8. Click **Test Connection** to verify.

### Option B: Direct Push to Elasticsearch

SecureAI can also push events directly to Elasticsearch without going through Elastic Agent. In this mode, the integration package still provides value through index templates, ingest pipelines, and field mappings.

#### Step 1: Obtain Your Elastic Cloud Endpoint

1. Log in to your Elastic Cloud account.
2. From the homepage, locate your desired deployment.
3. Find the Elasticsearch endpoint URL and copy it.

#### Step 2: Create an API Key in Elasticsearch

1. In Kibana, navigate to **Management** → **API Keys**.
2. Click **Create API key**.
3. Name it `secureai-siem-integration` and assign write privileges for the `logs-hiperai.events-*` index pattern.
4. Copy the Base64-encoded API key.

#### Step 3: Configure SecureAI

1. In the SecureAI admin console, navigate to **Integrations**.
2. Select the **Elastic SIEM** integration card.
3. Fill in the configuration:
   - **Integration Name**: `secureai-elastic`
   - **Elastic URL**: Your Elasticsearch endpoint URL
   - **Elastic API Key**: The Base64-encoded API key from Step 2
   - **Elastic Index**: `logs-hiperai.events-default`
   - **Event Categories**: Select the categories you want to forward
4. Click **Update** to save.

#### Step 4: Test the Connection

1. Click **Test Connection** in the integration settings.
2. Verify the test event appears in Kibana **Discover** under the `logs-hiperai.events-*` data view.

## Event Types

SecureAI forwards the following event types:

| Event Type | ECS Category | Description |
|---|---|---|
| `login_success` | `authentication` | Successful user authentication |
| `login_failed` | `authentication` | Failed authentication attempt |
| `logout` | `session` | User session ended |
| `chat_completion` | `process` | AI model chat completion request |
| `api_request` | `process` | API request processed |
| `policy_violation` | `intrusion_detection` | DLP or security policy violated |
| `security_incident` | `intrusion_detection` | Security incident detected |
| `smltp_violation` | `intrusion_detection` | SMLTP policy violation |
| `smltp_policy_applied` | `intrusion_detection` | SMLTP policy enforcement action |
| `smltp_entitlement_denied` | `intrusion_detection` | Model access denied by entitlement |
| `audit_log` | `configuration` | Administrative or audit action |
| `data_access` | `process` | Data access event |
| `billing_event` | `process` | Billing or usage event |

## Event Categories

Events can be filtered by the following categories in the SecureAI configuration:

- **Authentication & Login** — Login, logout, SSO, and MFA events
- **Security & Violations** — Policy violations, DLP triggers, prompt injection detection
- **SMLTP & Policy** — SMLTP governance, entitlement enforcement, policy actions
- **API & Model Usage** — AI model requests, token usage, response tracking
- **Data Access & PHI** — Data access events, PII/PHI detection
- **System & Infrastructure** — Platform health, service events
- **Configuration Changes** — Administrative and configuration modifications
- **Billing & Usage Limits** — Usage tracking and billing events
- **Analytics & Intelligence** — Platform analytics summaries
- **LLM Analytics** — AI model performance and usage analytics
- **Platform Intelligence** — Security posture and trend analysis
- **SMLTP Analytics** — Policy enforcement statistics
- **OCR Analytics** — Document processing analytics

## Severity Mapping

SecureAI severity levels are mapped to ECS numeric severity:

| SecureAI Severity | ECS `event.severity` |
|---|---|
| `info` | `1` |
| `low` | `2` |
| `medium` | `3` |
| `high` | `4` |
| `critical` | `5` |

## Logs reference

### Events

The `events` dataset collects all security events from the SecureAI platform.

{{event "events"}}

{{fields "events"}}

## Further Reading

- [HiperAI SecureAI Documentation](https://docs.hiperai.com)
- [SecureAI Elastic SIEM Integration Guide](https://docs.hiperai.com/integrations/elastic-security)
- [GitHub: Hiper-AI](https://github.com/Hiper-AI)
