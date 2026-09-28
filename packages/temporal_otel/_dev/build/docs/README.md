# Temporal Cloud OpenTelemetry Assets

Temporal Cloud is a fully managed Temporal service that provides durable workflow execution, task scheduling, and activity orchestration as a cloud platform. Customer applications connect to Temporal Cloud via gRPC and deploy their own worker processes, which poll Temporal Cloud for tasks and execute workflow and activity code.

This content pack provides dashboards, alert rules, and SLO templates for Temporal Cloud metrics collected via the **[Temporal](https://www.elastic.co/docs/reference/integrations/temporal)** integration package.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage
the Elastic Stack on your own hardware.

## Setup

Install the **Temporal** integration package and configure it with your Temporal Cloud credentials. This content pack provides assets that visualize data collected by that integration.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[Temporal OTel] Cloud Metrics** | Golden signals dashboard for Temporal Cloud covering latency, traffic, errors, and saturation — with KPI tiles, per-namespace time series, and capacity summary tables. |

## Alerting Rule Templates
{{alertRuleTemplates}}

## SLO Templates
{{sloTemplates}}
