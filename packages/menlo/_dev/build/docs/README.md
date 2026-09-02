# Menlo Security

Menlo Security’s isolation-centric approach splits web browsing and document retrieval between the user’s device and an isolated, Disposable Virtual Container (DVC) away from the endpoint. All risky code is executed in the isolated DVC and never reaches the endpoint. Only safe display data is sent to the user’s browser. User traffic is automatically sent to this infrastructure without any impact on the users themselves.

## Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

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
