# Menlo Security

Menlo Security’s isolation-centric approach splits web browsing and document retrieval between the user’s device and an isolated, Disposable Virtual Container (DVC) away from the endpoint. All risky code is executed in the isolated DVC and never reaches the endpoint. Only safe display data is sent to the user’s browser. User traffic is automatically sent to this infrastructure without any impact on the users themselves.

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Web

Menlo Security's cloud based Browser Security prevents phishing and malware attacks on any browser and any device across your hybrid enterprise.

## DLP

Data Loss Prevention (also known as Data Leak Prevention) detects potential data breaches or data ex-filtration transmissions and prevents them by detecting and optionally blocking sensitive data passing through the Menlo Security platform.

## Compatibility

This module has been tested against the Menlo Security API **version 2.0**

## Data streams

The Menlo Security integration collects data for the following two events:

| Event Type                    |
|-------------------------------|
| Web                           |
| DLP                           |

## Setup

To collect data through the REST API you will need your Menlo Security API URL and an API token.

The API token to collect logs must have the *Log Export API* permission

## Logs Reference

### Web

This is the `Web` dataset.

#### Example

{{ event "web" }}

{{ fields "web" }}

### DLP

This is the `DLP` dataset.

#### Example

{{ event "dlp" }}

{{ fields "dlp" }}
