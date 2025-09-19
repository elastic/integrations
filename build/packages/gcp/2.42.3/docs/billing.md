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
    
An example event for `billing` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "cloud": {
        "account": {
            "id": "01475F-5B1080-1137E7"
        },
        "project": {
            "id": "elastic-bi",
            "name": "elastic-containerlib-prod"
        },
        "provider": "gcp"
    },
    "event": {
        "dataset": "gcp.billing",
        "duration": 115000,
        "module": "gcp"
    },
    "gcp": {
        "billing": {
            "billing_account_id": "01475F-5B1080-1137E7",
            "cost_type": "regular",
            "invoice_month": "202106",
            "project_id": "containerlib-prod-12763",
            "project_name": "elastic-containerlib-prod",
            "total": 4717.170681,
            "sku_id": "0D56-2F80-52A5",
            "service_id": "6F81-5844-456A",
            "sku_description": "Network Inter Region Ingress from Jakarta to Americas",
            "service_description": "Compute Engine",
            "effective_price": 0.00292353,
            "tags": [
                {
                    "key": "stage",
                    "value": "prod"
                },
                {
                    "key": "size",
                    "value": "standard"
                }
            ]
        }
    },
    "metricset": {
        "name": "billing",
        "period": 10000
    },
    "service": {
        "type": "gcp"
    }
}
```

## Exported fields

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| gcp.billing.billing_account_id | Project Billing Account ID. | keyword |
| gcp.billing.cost_type | Cost types include regular, tax, adjustment, and rounding_error. | keyword |
| gcp.billing.effective_price | The charged price for usage of the Google Cloud SKUs and SKU tiers. Reflects contract pricing if applicable, otherwise, it's the list price. | float |
| gcp.billing.invoice_month | Billing report month. | keyword |
| gcp.billing.project_id | Project ID of the billing report belongs to. | keyword |
| gcp.billing.project_name | Project Name of the billing report belongs to. | keyword |
| gcp.billing.service_description | The Google Cloud service that reported the Cloud Billing data. | keyword |
| gcp.billing.service_id | The ID of the service that the usage is associated with. | keyword |
| gcp.billing.sku_description | A description of the resource type used by the service. For example, a resource type for Cloud Storage is Standard Storage US. | keyword |
| gcp.billing.sku_id | The ID of the resource used by the service. | keyword |
| gcp.billing.tags | A collection of key-value pairs that provide additional metadata. | nested |
| gcp.billing.tags.key |  | keyword |
| gcp.billing.tags.value |  | keyword |
| gcp.billing.total | Total billing amount. | float |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
