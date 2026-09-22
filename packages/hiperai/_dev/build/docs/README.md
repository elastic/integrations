# HiperAI SecureAI

## Overview

The HiperAI SecureAI integration for Elastic enables you to monitor and analyze security events from [SecureAI](https://hiperai.com), an enterprise security, data loss prevention (DLP), and governance platform for generative AI and large language model (LLM) workflows. This integration collects authentication activity, AI model usage, policy enforcement decisions, DLP triggers, and audit logs, so you can correlate AI-specific security events with the rest of your enterprise telemetry in Elastic Security.

### Compatibility

This integration is compatible with SecureAI version 1.1.x and later. SecureAI must be able to reach the Elastic Agent HTTP listener over the network to deliver events.

### How it works

SecureAI pushes security events to Elastic rather than Elastic polling SecureAI. The integration starts an HTTP listener on an Elastic Agent using the `http_endpoint` input, and you configure the SecureAI Elastic SIEM integration to send events to that listener as JSON over HTTP.

Every request must carry a shared secret in a header that you choose, and the listener rejects requests that do not present the expected value. Received events are normalized to the Elastic Common Schema (ECS) by the integration's ingest pipeline, which sets event categorization, maps the SecureAI severity label to the Elastic severity scale, and enriches source IP addresses with geolocation and autonomous system data. Platform-specific values that have no ECS equivalent are preserved under the `hiperai.*` namespace.

## What data does this integration collect?

The HiperAI SecureAI integration collects security and governance events from the SecureAI platform in the `events` data stream, including:

- Authentication activity: successful and failed logins, and session termination.
- AI model usage: chat completions, API requests, and data access events.
- Policy enforcement: DLP and security policy violations, prompt injection detections, and security incidents.
- SMLTP governance: Secure Model Link Transport Protocol policy violations, enforcement actions, and entitlement denials.
- Administrative activity: configuration changes, audit logs, and billing or usage events.

You choose which of these categories SecureAI forwards, in the SecureAI console.

### Supported use cases

- AI usage monitoring: track which users and applications are calling which models, and correlate that activity with the rest of your security telemetry.
- Data loss prevention for AI: investigate attempts to send personally identifiable information (PII), protected health information (PHI), credentials, or confidential data to AI models.
- Governance and policy enforcement: audit SMLTP policy decisions and model entitlement denials.
- Threat detection: detect prompt injection attempts and other adversarial activity against AI workflows.
- Compliance and audit: retain an auditable record of AI interactions and administrative changes.

## What do I need to use this integration?

You need the following Elastic components:

- An Elastic Stack deployment, either self-managed or on Elastic Cloud.
- An Elastic Agent enrolled in Fleet, installed on a host that SecureAI can reach over the network.
- A port on that host that is reachable from SecureAI, and open in any firewall between the two. The integration listens on port `8089` by default.

You also need the following on the SecureAI side:

- A SecureAI deployment running version 1.1.x or later.
- An administrator account with access to the SecureAI console, to configure the Elastic SIEM integration.

## How do I deploy this integration?

### Onboard and configure

This integration receives data through an HTTP listener on an Elastic Agent, so the agent must be installed before you configure SecureAI. Agentless deployment is not supported, because SecureAI must be able to reach a listener that you control.

Follow these steps in Kibana:

1. Navigate to **Management > Integrations**.
2. Search for and select **HiperAI SecureAI**.
3. Click **Add HiperAI SecureAI**.
4. Configure the listener:
    - **Listen Port**: the port the agent listens on. The default is `8089`.
    - **URL Path**: the path the listener accepts requests on. The default is `/hiperai/events`.
    - **Secret Header**: the name of the HTTP header that carries the shared secret, for example `Authorization`.
    - **Secret Value**: the value the listener requires in that header. For API key authentication, use the format `ApiKey <base64-encoded-key>`.
    - **TLS/SSL Configuration** (optional, under advanced options): serve the listener over HTTPS. Configure this whenever SecureAI reaches the agent over an untrusted network.
5. Select the agent policy to deploy to, and click **Save and continue**.

Then configure the delivery side in SecureAI:

1. In the SecureAI console, navigate to **Integrations** and select the **Elastic SIEM** integration.
2. Set the destination URL to the Elastic Agent listener, including the URL path you configured, for example `http://<agent-host>:8089/hiperai/events`.
3. Set the authentication header to the **Secret Header** and **Secret Value** you configured in step 4. Both are required, and SecureAI must send this header on every request.
4. Select the event categories you want to forward.
5. Click **Test Connection**, then save the configuration.

#### Alternative: deliver events directly to Elasticsearch

SecureAI can also write events directly to Elasticsearch instead of going through an Elastic Agent. In this mode you still install this integration's assets, because the index template, ingest pipeline, and field mappings are what normalize the events. Configure SecureAI with your Elasticsearch endpoint, an API key with write privileges for the `logs-hiperai.events-*` indices, and the index `logs-hiperai.events-default`.

#### Vendor resources

- [HiperAI SecureAI documentation](https://docs.hiperai.com)
- [SecureAI Elastic SIEM integration guide](https://docs.hiperai.com/integrations/elastic-security)

### Validation

To confirm that events are arriving and are being processed correctly:

1. In the SecureAI console, click **Test Connection** in the Elastic SIEM integration settings, or generate activity such as a login.
2. In Kibana, navigate to **Analytics > Discover**.
3. Select the `logs-*` data view and filter with the following KQL query: `data_stream.dataset : "hiperai.events"`.
4. Confirm that documents contain normalized fields such as `event.category`, `event.action`, `event.severity`, and the SecureAI-specific `hiperai.*` fields.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

If events do not appear in Elasticsearch:

- Confirm the listener is reachable from SecureAI. From a host on the same network, send a test request to `http://<agent-host>:<port>/<url-path>` and confirm it is not blocked by a firewall or security group.
- Confirm the secret matches. If SecureAI sends a header value that differs from **Secret Value**, or omits the header, the listener rejects the request. SecureAI reports this as a failed connection test.
- Confirm the URL path matches. A request sent to the host and port but to a different path than **URL Path** is not accepted.
- Check the Elastic Agent logs for the `http_endpoint` input, which reports binding failures such as a port already in use.
- Confirm that the port is not already claimed by another integration on the same agent. Each HTTP listener on a host needs its own port.

If events arrive but fields are missing or wrong:

- Check for documents where `event.kind` is `pipeline_error`, and read `error.message` to see which processor failed.
- Confirm SecureAI is sending the event types you expect. Events whose type and category are both unrecognized are still ingested, but they are not categorized.

For further assistance with SecureAI, refer to the [HiperAI SecureAI documentation](https://docs.hiperai.com).

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

Consider the following when planning a deployment:

- Event volume is controlled at the source. Select only the event categories you need in the SecureAI console. Analytics categories in particular can be high volume and are rarely needed for security investigations.
- Scale out by adding listeners. Because delivery is push-based, you scale by running the integration on additional agents and distributing SecureAI's delivery across them, typically behind a load balancer that terminates TLS.
- The listener applies backpressure. If Elasticsearch slows down, the agent stops accepting new requests, and SecureAI retries according to its own delivery settings.

## Reference

### Inputs used

{{ inputDocs }}

### Event types

SecureAI forwards the following event types, which the integration maps to ECS categories:

| Event type | ECS category | Description |
|---|---|---|
| `login_success` | `authentication` | Successful user authentication |
| `login_failed` | `authentication` | Failed authentication attempt |
| `logout` | `session` | User session ended |
| `chat_completion` | `api` | AI model chat completion request |
| `api_request` | `api` | API request processed |
| `policy_violation` | `intrusion_detection` | DLP or security policy violated |
| `security_incident` | `intrusion_detection` | Security incident detected |
| `smltp_violation` | `intrusion_detection` | SMLTP policy violation |
| `smltp_policy_applied` | `intrusion_detection` | SMLTP policy enforcement action |
| `smltp_entitlement_denied` | `intrusion_detection` | Model access denied by entitlement |
| `audit_log` | `configuration` | Administrative or audit action |
| `data_access` | `api` | Data access event |
| `billing_event` | `api` | Billing or usage event |

An event whose type is not listed above is categorized from its SecureAI category instead.

### Severity mapping

SecureAI severity labels are mapped to `event.severity` using the Elastic severity scale, so values are comparable with other integrations:

| SecureAI severity | ECS `event.severity` |
|---|---|
| `info` | `21` |
| `low` | `21` |
| `medium` | `47` |
| `high` | `73` |
| `critical` | `99` |

### Vendor documentation links

- [HiperAI SecureAI documentation](https://docs.hiperai.com)
- [SecureAI Elastic SIEM integration guide](https://docs.hiperai.com/integrations/elastic-security)

### Data streams

#### events

The `events` data stream collects all security, governance, and audit events forwarded by the SecureAI platform.

{{ event "events" }}

##### events fields

{{ fields "events" }}
