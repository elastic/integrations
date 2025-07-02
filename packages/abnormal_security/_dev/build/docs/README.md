# Abnormal AI

Abnormal AI is a behavioral AI-based email security platform that learns the behavior of every identity in a cloud email environment and analyzes the risk of every event to block even the most sophisticated attacks.

The Abnormal AI integration collects data for AI Security Mailbox (formerly known as Abuse Mailbox), Audit, Case, and Threat logs using REST API.

## Data streams

The Abnormal AI integration collects six types of logs:

- **[AI Security Mailbox](https://app.swaggerhub.com/apis-docs/abnormal-security/abx/1.4.3#/AI%20Security%20Mailbox%20(formerly%20known%20as%20Abuse%20Mailbox))** - Get details of AI Security Mailbox.

- **[AI Security Mailbox Not Analyzed](https://app.swaggerhub.com/apis/abnormal-security/abx/1.4.3#/AI%20Security%20Mailbox%20(formerly%20known%20as%20Abuse%20Mailbox)/v1_abuse_mailbox_not_analyzed_retrieve)** - Get details of messages submitted to AI Security Mailbox that were not analyzed.

- **[Audit](https://app.swaggerhub.com/apis-docs/abnormal-security/abx/1.4.3#/Audit%20Logs)** - Get details of Audit logs for Portal.

- **[Case](https://app.swaggerhub.com/apis-docs/abnormal-security/abx/1.4.3#/Cases)** - Get details of Abnormal Cases.

- **[Threat](https://app.swaggerhub.com/apis-docs/abnormal-security/abx/1.4.3#/Threats)** - Get details of Abnormal Threat Logs.

- **[Vendor Case](https://app.swaggerhub.com/apis-docs/abnormal-security/abx/1.4.3#/Vendors)** - Get details of Abnormal Vendor Cases.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### To collect data from the Abnormal AI Client API:

#### Step 1: Go to Portal
* Visit the [Abnormal AI Portal](https://portal.abnormalsecurity.com/home/settings/integrations) and click on the `Abnormal REST API` setting.

#### Step 2: Generating the authentication token
* Retrieve your authentication token. This token will be used further in the Elastic integration setup to authenticate and access different Abnormal AI Logs.

#### Step 3: IP allowlisting
* Abnormal AI requires you to restrict API access based on source IP. So in order for the integration to work, user needs to update the IP allowlisting to include the external source IP of the endpoint running the integration via Elastic Agent.

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Abnormal AI`.
3. Select the "Abnormal AI" integration from the search results.
4. Select "Add Abnormal AI" to add the integration.
5. Add all the required integration configuration parameters, including Access Token, Interval, Initial Interval and Page Size to enable data collection.
6. Select "Save and continue" to save the integration.

**Note**: By default, the URL is set to `https://api.abnormalplatform.com`. We have observed that Abnormal AI Base URL changes based on location so find your own base URL.

### Enabling enrichment for Threat events

Introduced in version 1.8.0, the Abnormal AI integration includes a new option called `Enable Attachments and Links enrichment` for the Threat data stream. When enabled, this feature enriches incoming threat events with additional details about any attachments and links included in the original message.

## Logs reference

### AI Security Mailbox

This is the `ai_security_mailbox` dataset.

#### Example

{{event "ai_security_mailbox"}}

{{fields "ai_security_mailbox"}}

### AI Security Mailbox Not Analyzed

This is the `ai_security_mailbox_not_analyzed` dataset.

#### Example

{{event "ai_security_mailbox_not_analyzed"}}

{{fields "ai_security_mailbox_not_analyzed"}}

### Audit

This is the `audit` dataset.

#### Example

{{event "audit"}}

{{fields "audit"}}

### Case

This is the `case` dataset.

#### Example

{{event "case"}}

{{fields "case"}}

### Vendor Case

This is the `vendor_case` dataset.

#### Example

{{event "vendor_case"}}

{{fields "vendor_case"}}

### Threat

This is the `threat` dataset.

#### Example

{{event "threat"}}

{{fields "threat"}}
