# Billing

## Metrics

The `billing` dataset collects [Cloud Billing Reports](https://cloud.google.com/billing/docs/reports) information from Google Cloud BigQuery daily cost detail table. BigQuery is a fully-managed, serverless data warehouse. Cloud Billing export to BigQuery enables you to export detailed Google Cloud billing data (such as usage, cost estimates, and pricing data) automatically throughout the day to a BigQuery dataset that you specify. Then you can access your Cloud Billing data from BigQuery for detailed analysis.

Please see [export cloud billing data to BigQuery](https://cloud.google.com/billing/docs/how-to/export-data-bigquery) for more details on how to export billing data.

In BigQuery dataset, detailed Google Cloud daily cost data is loaded into a data table named `gcp_billing_export_v1_<BILLING_ACCOUNT_ID>`. There is a defined schema for Google Cloud daily cost data that is exported to BigQuery. Please see [daily cost detail data schema](https://cloud.google.com/billing/docs/how-to/export-data-bigquery-tables#data-schema) for more details.

For standard usage cost data, set the table pattern format to `gcp_billing_export_v1`. This table pattern is set as the default when no other is specified.

For detailed usage cost data, set the table pattern to `gcp_billing_export_resource_v1`. Detailed tables include the standard fields and additional fields, such as `effective_price`, enabling a more granular view of expenses.

## Sample Event
    
{{event "billing"}}

## Exported fields

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "billing"}}