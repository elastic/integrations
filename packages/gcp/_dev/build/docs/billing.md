# Billing

## Metrics

The `billing` dataset collects [Cloud Billing Reports](https://cloud.google.com/billing/docs/reports) information from Google Cloud BigQuery daily cost detail table. BigQuery is a fully-managed, serverless data warehouse. Cloud Billing export to BigQuery enables you to export detailed Google Cloud billing data (such as usage, cost estimates, and pricing data) automatically throughout the day to a BigQuery dataset that you specify. Then you can access your Cloud Billing data from BigQuery for detailed analysis.

Please see [export cloud billing data to BigQuery](https://cloud.google.com/billing/docs/how-to/export-data-bigquery) for more details on how to export billing data.

In BigQuery dataset, detailed Google Cloud daily cost data is loaded into a data table named `gcp_billing_export_v1_<BILLING_ACCOUNT_ID>`. There is a defined schema for Google Cloud daily cost data that is exported to BigQuery. Please see [daily cost detail data schema](https://cloud.google.com/billing/docs/how-to/export-data-bigquery-tables#data-schema) for more details.

For standard usage cost data, set the table pattern format to `gcp_billing_export_v1`. This table pattern is set as the default when no other is specified.

For detailed usage cost data, set the table pattern to `gcp_billing_export_resource_v1`. Detailed tables include the standard fields and additional fields, such as `effective_price`, enabling a more granular view of expenses.

## Configuration Parameters

### dataset_id

The `dataset_id` is the ID of your BigQuery dataset where your billing data is stored. This is a unique identifier for the dataset within the project. You can find this ID in your Google Cloud Console under BigQuery.

### table_pattern

The `table_pattern` defines which tables to pull from within the specified dataset. This can be set to either `gcp_billing_export_v1` for standard usage cost data or `gcp_billing_export_resource_v1` for detailed usage cost data.

## Example Configuration

Here's an example of what your configuration might look like:

```
dataset_id: "my_billing_dataset"
table_pattern: "gcp_billing_export_resource_v1"
project_id: "my_project"
cost_type: "regular"
```

In this example, the agent will pull data from the `gcp_billing_export_resource_v1` table within the `my_billing_dataset` dataset.

## Sample Event
    
{{event "billing"}}

## Exported fields

{{fields "billing"}}