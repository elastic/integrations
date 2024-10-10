# Billing

## Metrics

The `billing` dataset collects [Cloud Billing Reports](https://cloud.google.com/billing/docs/reports) information from Google Cloud BigQuery daily cost detail table. BigQuery is a fully-managed, serverless data warehouse. Cloud Billing export to BigQuery enables you to export detailed Google Cloud billing data (such as usage, cost estimates, and pricing data) automatically throughout the day to a BigQuery dataset that you specify. Then you can access your Cloud Billing data from BigQuery for detailed analysis.

Please see [export cloud billing data to BigQuery](https://cloud.google.com/billing/docs/how-to/export-data-bigquery) for more details on how to export billing data.

In BigQuery dataset, detailed Google Cloud daily cost data is loaded into a data table named `gcp_billing_export_v1_<BILLING_ACCOUNT_ID>`. There is a defined schema for Google Cloud daily cost data that is exported to BigQuery. Please see [daily cost detail data schema](https://cloud.google.com/billing/docs/how-to/export-data-bigquery-tables#data-schema) for more details.

For standard usage cost data, set the table pattern format to `gcp_billing_export_v1`. This table pattern is set as the default when no other is specified.

For detailed usage cost data, set the table pattern to `gcp_billing_export_resource_v1`. Detailed tables include the standard fields and additional fields, such as `effective_price`, enabling a more granular view of expenses.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any GCP integration you will need:

* **GCP Credentials** to connect with your GCP account.
* **GCP Permissions** to make sure the service account you're using to connect has permission to share the relevant data.

To collect GCP Billing metrics, the following permissions are required to access the necessary data:

- `roles/bigquery.dataViewer`
- `roles/bigquery.jobUser`
- `roles/billing.viewer`

## Configuration Parameters

### dataset_id

The `dataset_id` is the unique identifier of your BigQuery dataset where your billing data is stored. You can find this ID in your Google Cloud Console under the BigQuery section.

### table_pattern

The `table_pattern` parameter allows you to specify which tables to retrieve from the specified dataset. This can be set to either `gcp_billing_export_v1` for standard usage cost data or `gcp_billing_export_resource_v1` for detailed usage cost data.

### cost_type

The `cost_type` parameter enables you to filter the cost data based on specific cost categories. You can select one of the following options:

- `regular`: This cost type includes all the regular costs associated with your usage of GCP services. This does not include any taxes, adjustments, or rounding errors.

- `tax`: This cost type includes all the taxes associated with your usage of GCP services. This does not include the regular costs, adjustments, or rounding errors.

- `adjustment`: This cost type includes any adjustments made to your billing data. Adjustments can include credits, discounts, refunds, or any other modifications to the original costs.

- `rounding_error`: This cost type includes any rounding errors that occurred when calculating your costs. These are typically very small amounts and are used to reconcile any discrepancies due to rounding.

## Example Configuration

Here's an example of what your configuration might look like:

```
dataset_id: "my_billing_dataset"
table_pattern: "gcp_billing_export_resource_v1"
project_id: "my_project"
cost_type: "regular"
```

In this example, the Agent will pull data from all tables within the `my_billing_dataset` dataset that start with the pattern `gcp_billing_export_resource_v1`.

## Sample Event
    
{{event "billing"}}

## Exported fields

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "billing"}}