# AWS CUR 2.0 Billing

## Overview

[Amazon Cost and Usage Reports (CUR)](https://docs.aws.amazon.com/cur/latest/userguide/what-is-cur.html) provide the most detailed information available about your AWS costs and usage. CUR 2.0 enhances this reporting format with greater structure and compatibility for analytics.

The **AWS CUR 2.0 Billing integration** allows you to seamlessly collect and ingest Cost and Usage Report (CUR) version 2.0 data exported to an Amazon S3 bucket, using the Elastic Agent. This enables you to monitor, analyze, and visualize AWS billing data with the power of the Elastic Stack.

This integration is designed specifically to support standard CUR 2.0 exports with predefined configuration requirements.

> **IMPORTANT:** The integration currently supports only CUR 2.0 reports **without** resource IDs and **split cost allocation data**, and requires a very specific configuration of the CUR export.

## Compatibility

This integration supports CUR 2.0 reports only with the specified configurations. If your report includes resource IDs or split allocation data, the integration **will not work**.

## Data Streams

This integration collects data into a single stream:

* `billing`: Contains all metrics from your CUR 2.0 billing reports.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for
visualizing and managing it. You can use our hosted Elasticsearch Service on
Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your
own hardware.

Before using this integration, ensure the following:

### AWS Cost and Usage Report (CUR) Export

To use this integration, you must first create a **standard CUR 2.0 data export** in AWS. This will automatically create an S3 bucket if one does not already exist.

#### Required CUR Export Configuration

When creating your CUR export, the following **configuration is required** for compatibility:

* **Compression type and file format**: `gzip - text/csv`
* **File versioning**: `Overwrite existing data export file`
* **Additional export content**:

  * **Include resource IDs**: ❌ Disabled
  * **Split cost allocation data**: ❌ Disabled
  * **Include all available columns (113 total)**: ✅ Default
* **S3 bucket**: Must exist and be accessible by the Elastic Agent.

You can follow AWS documentation for setup:
🔗 [Creating Cost and Usage Reports in AWS](https://docs.aws.amazon.com/cur/latest/userguide/cur-create.html)

#### S3 Bucket Configuration

* Ensure the **S3 bucket used for the CUR export is accessible** via the credentials provided to the Elastic Agent.
* The integration requires **ListBucket** permission on the bucket.

### Minimum Bucket Polling Interval: **24 Hours**

CUR 2.0 reports are cumulative, meaning they are overwritten daily with the full billing data. Therefore, **setting the bucket polling interval to less than 24 hours will result in duplicate ingestion** of the same data.

> ✅ **REQUIRED:** Set the **S3 polling interval** to **at least 24 hours** to avoid duplicating report ingestion.

Learn more:
🔗 [Understanding CUR Overwrite Behavior](https://docs.aws.amazon.com/cur/latest/userguide/what-is-data-exports.html)

### AWS Permissions

The credentials used by the Elastic Agent must have appropriate AWS IAM permissions, such as:

* `s3:GetObject`
* `s3:ListBucket`
* (optional if using role assumption) `sts:AssumeRole`

Refer to the [AWS integration documentation](https://docs.elastic.co/integrations/aws#requirements) for more details on required permissions and credential setup.

### Elastic Agent

* You must install and configure [Elastic Agent](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html) to collect and ship data from the S3 bucket.
* Only one Elastic Agent should be installed per host.

## Setup

1. In AWS, [create a CUR 2.0 export](https://docs.aws.amazon.com/cur/latest/userguide/cur-create.html) with the required settings.
2. Ensure the report is stored in a reachable S3 bucket with proper permissions.
3. Configure this integration in Elastic using the required AWS credentials or role.
4. Set the S3 polling interval to **24h** (minimum).
5. Monitor the `billing` data stream in Kibana for insights and visualizations.

## Metrics

### CUR Metrics

AWS CUR contains all metrics from your CUR 2.0 billing reports.

An example event for `cur` looks as following:

```json
{
    "aws_billing": {
        "cur": {
            "bill": {
                "billing_entity": "BillingEntity",
                "billing_period_end_date": "2025-08-01T00:00:00.000Z",
                "billing_period_start_date": "2025-07-01T00:00:00.000Z",
                "invoicing_entity": "Amazon Web Services, Inc.",
                "payer_account_id": "123456789012",
                "payer_account_name": "tech-innovators",
                "type": "Bill"
            },
            "cost_category": "{\"cloud_discount\":\"10%\"}",
            "discount": {
                "total_discount": 0.0
            },
            "identity": {
                "line_item_id": "abcdef12345ghjklmnpq789xyz",
                "time_interval": "2025-07-01T00:00:00Z/2025-08-01T00:00:00Z"
            },
            "line_item": {
                "blended_cost": 120.0,
                "currency_code": "USD",
                "description": "Tax for product code EC2 usage type APN2-EC2:Compute",
                "legal_entity": "Amazon Web Services, Inc.",
                "net_unblended_cost": 12.0,
                "normalization_factor": 120.0,
                "normalized_usage_amount": 12.0,
                "product_code": "AmazonEC2",
                "tax_type": "CT",
                "type": "Tax",
                "unblended_cost": 100.0,
                "usage_account_id": "450345623178",
                "usage_account_name": "tech-solutions",
                "usage_amount": 1.0,
                "usage_end_date": "2025-08-01T00:00:00.000Z",
                "usage_start_date": "2025-07-01T00:00:00.000Z",
                "usage_type": "APN2-EC2:Compute"
            },
            "pricing": {
                "public_on_demand_cost": 0.0
            },
            "product": {
                "product": "{\"product_name\":\"AmazonEC2\"}"
            },
            "reservation": {
                "amortized_upfront_cost_for_usage": 0.0,
                "amortized_upfront_fee_for_billing_period": 0.0,
                "effective_cost": 0.0,
                "net_amortized_upfront_cost_for_usage": 0.0,
                "net_amortized_upfront_fee_for_billing_period": 0.0,
                "net_effective_cost": 0.0,
                "net_recurring_fee_for_usage": 0.0,
                "net_unused_amortized_upfront_fee_for_billing_period": 0.0,
                "net_unused_recurring_fee": 0.0,
                "net_upfront_value": 0.0,
                "recurring_fee_for_usage": 0.0,
                "unused_amortized_upfront_fee_for_billing_period": 0.0,
                "unused_normalized_unit_quantity": 0.0,
                "unused_quantity": 0.0,
                "unused_recurring_fee": 0.0,
                "upfront_value": 0.0
            },
            "resource_tags": "{\"CostCenter\":\"AI-421\",\"Department\":\"AI Research\",\"Environment\":\"Production\",\"Owner\":\"alice.wang\",\"Project\":\"NeuralNet-ML\"}",
            "savings_plan": {
                "amortized_upfront_commitment_for_billing_period": 0.0,
                "effective_cost": 0.0,
                "net_amortized_upfront_commitment_for_billing_period": 0.0,
                "net_effective_cost": 0.0,
                "net_recurring_commitment_for_billing_period": 0.0,
                "rate": 0.0,
                "recurring_commitment_for_billing_period": 0.0,
                "total_commitment_to_date": 0.0,
                "used_commitment": 0.0
            }
        }
    },
    "cloud": {
        "provider": "aws"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "category": [
            "web"
        ],
        "kind": "event",
        "original": "Bill,BillingEntity,2025-08-01T00:00:00.000Z,2025-07-01T00:00:00.000Z,,\"Amazon Web Services, Inc.\",123456789012,tech-innovators,\"{\"\"cloud_discount\"\":\"\"10%\"\"}\",\"{\"\"enterprise_rate\"\":\"\"15%\"\"}\",,0.0,abcdef12345ghjklmnpq789xyz,2025-07-01T00:00:00Z/2025-08-01T00:00:00Z,,120.0,,USD,\"Amazon Web Services, Inc.\",Tax for product code EC2 usage type APN2-EC2:Compute,Tax,12.0,,120.0,12.0,,AmazonEC2,CT,100.0,,450345623178,tech-solutions,1.0,2025-08-01T00:00:00.000Z,2025-07-01T00:00:00.000Z,APN2-EC2:Compute,,,,0.0,,,,,,,\"{\"\"product_name\"\":\"\"AmazonEC2\"\"}\",,,,,,,,,,,,,,,,,,,,,,0.0,0.0,,0.0,,,0.0,0.0,0.0,0.0,0.0,0.0,0.0,\"\",\"\",0.0,,,,\"\",\"\",\"\",0.0,0.0,0.0,0.0,0.0,\"{\"\"Environment\"\":\"\"Production\"\",\"\"Owner\"\":\"\"alice.wang\"\",\"\"Project\"\":\"\"NeuralNet-ML\"\",\"\"Department\"\":\"\"AI Research\"\",\"\"CostCenter\"\":\"\"AI-421\"\"}\",0.0,,,0.0,0.0,0.0,,,,0.0,,,0.0,0.0,,0.0,0.0"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields"
    ]
}
```
**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| aws.cloudwatch.message | CloudWatch log message. | text |
| aws.s3.bucket.arn | ARN of the S3 bucket that this log retrieved from. | keyword |
| aws.s3.bucket.name | Name of the S3 bucket that this log retrieved from. | keyword |
| aws.s3.object.key | Name of the S3 object that this log retrieved from. | keyword |
| aws_billing.cur.bill.billing_entity |  | keyword |
| aws_billing.cur.bill.billing_period_end_date |  | date |
| aws_billing.cur.bill.billing_period_start_date |  | date |
| aws_billing.cur.bill.invoice_id |  | keyword |
| aws_billing.cur.bill.invoicing_entity |  | keyword |
| aws_billing.cur.bill.payer_account_id |  | keyword |
| aws_billing.cur.bill.payer_account_name |  | keyword |
| aws_billing.cur.bill.type |  | keyword |
| aws_billing.cur.bundled_discount |  | double |
| aws_billing.cur.cost.amortized_cost |  | double |
| aws_billing.cur.cost.net_amortized_cost |  | double |
| aws_billing.cur.cost_category |  | keyword |
| aws_billing.cur.discount |  | object |
| aws_billing.cur.identity.line_item_id |  | keyword |
| aws_billing.cur.identity.time_interval |  | keyword |
| aws_billing.cur.line_item.availability_zone |  | keyword |
| aws_billing.cur.line_item.blended_cost |  | double |
| aws_billing.cur.line_item.blended_rate |  | double |
| aws_billing.cur.line_item.currency_code |  | keyword |
| aws_billing.cur.line_item.description |  | text |
| aws_billing.cur.line_item.legal_entity |  | keyword |
| aws_billing.cur.line_item.net_unblended_cost |  | double |
| aws_billing.cur.line_item.net_unblended_rate |  | double |
| aws_billing.cur.line_item.normalization_factor |  | double |
| aws_billing.cur.line_item.normalized_usage_amount |  | double |
| aws_billing.cur.line_item.operation |  | keyword |
| aws_billing.cur.line_item.product_code |  | keyword |
| aws_billing.cur.line_item.resource_id |  | keyword |
| aws_billing.cur.line_item.tax_type |  | keyword |
| aws_billing.cur.line_item.type |  | keyword |
| aws_billing.cur.line_item.unblended_cost |  | double |
| aws_billing.cur.line_item.unblended_cost_str |  | keyword |
| aws_billing.cur.line_item.unblended_rate |  | double |
| aws_billing.cur.line_item.usage_account_id |  | keyword |
| aws_billing.cur.line_item.usage_account_name |  | keyword |
| aws_billing.cur.line_item.usage_amount |  | double |
| aws_billing.cur.line_item.usage_end_date |  | date |
| aws_billing.cur.line_item.usage_start_date |  | date |
| aws_billing.cur.line_item.usage_type |  | keyword |
| aws_billing.cur.pricing.currency |  | keyword |
| aws_billing.cur.pricing.lease_contract_length |  | keyword |
| aws_billing.cur.pricing.offering_class |  | keyword |
| aws_billing.cur.pricing.public_on_demand_cost |  | double |
| aws_billing.cur.pricing.public_on_demand_rate |  | double |
| aws_billing.cur.pricing.purchase_option |  | keyword |
| aws_billing.cur.pricing.rate_code |  | keyword |
| aws_billing.cur.pricing.rate_id |  | keyword |
| aws_billing.cur.pricing.term |  | keyword |
| aws_billing.cur.pricing.unit |  | keyword |
| aws_billing.cur.product.comment |  | text |
| aws_billing.cur.product.family |  | keyword |
| aws_billing.cur.product.fee_code |  | keyword |
| aws_billing.cur.product.fee_description |  | text |
| aws_billing.cur.product.from_location |  | keyword |
| aws_billing.cur.product.from_location_type |  | keyword |
| aws_billing.cur.product.from_region_code |  | keyword |
| aws_billing.cur.product.instance_family |  | keyword |
| aws_billing.cur.product.instance_type |  | keyword |
| aws_billing.cur.product.instancesku |  | keyword |
| aws_billing.cur.product.location |  | keyword |
| aws_billing.cur.product.location_type |  | keyword |
| aws_billing.cur.product.operation |  | keyword |
| aws_billing.cur.product.pricing_unit |  | keyword |
| aws_billing.cur.product.product |  | keyword |
| aws_billing.cur.product.region_code |  | keyword |
| aws_billing.cur.product.servicecode |  | keyword |
| aws_billing.cur.product.sku |  | keyword |
| aws_billing.cur.product.to_location |  | keyword |
| aws_billing.cur.product.to_location_type |  | keyword |
| aws_billing.cur.product.to_region_code |  | keyword |
| aws_billing.cur.product.usagetype |  | keyword |
| aws_billing.cur.reservation.a_r_n |  | keyword |
| aws_billing.cur.reservation.amortized_upfront_cost_for_usage |  | double |
| aws_billing.cur.reservation.amortized_upfront_fee_for_billing_period |  | double |
| aws_billing.cur.reservation.availability_zone |  | keyword |
| aws_billing.cur.reservation.effective_cost |  | double |
| aws_billing.cur.reservation.end_time |  | date |
| aws_billing.cur.reservation.modification_status |  | keyword |
| aws_billing.cur.reservation.net_amortized_upfront_cost_for_usage |  | double |
| aws_billing.cur.reservation.net_amortized_upfront_fee_for_billing_period |  | double |
| aws_billing.cur.reservation.net_effective_cost |  | double |
| aws_billing.cur.reservation.net_recurring_fee_for_usage |  | double |
| aws_billing.cur.reservation.net_unused_amortized_upfront_fee_for_billing_period |  | double |
| aws_billing.cur.reservation.net_unused_recurring_fee |  | double |
| aws_billing.cur.reservation.net_upfront_value |  | double |
| aws_billing.cur.reservation.normalized_units_per_reservation |  | double |
| aws_billing.cur.reservation.number_of_reservations |  | double |
| aws_billing.cur.reservation.recurring_fee_for_usage |  | double |
| aws_billing.cur.reservation.start_time |  | date |
| aws_billing.cur.reservation.subscription_id |  | keyword |
| aws_billing.cur.reservation.total_reserved_normalized_units |  | double |
| aws_billing.cur.reservation.total_reserved_units |  | double |
| aws_billing.cur.reservation.units_per_reservation |  | double |
| aws_billing.cur.reservation.unused_amortized_upfront_fee_for_billing_period |  | double |
| aws_billing.cur.reservation.unused_normalized_unit_quantity |  | double |
| aws_billing.cur.reservation.unused_quantity |  | double |
| aws_billing.cur.reservation.unused_recurring_fee |  | double |
| aws_billing.cur.reservation.upfront_value |  | double |
| aws_billing.cur.resource.tags |  | keyword |
| aws_billing.cur.resource_tags |  | keyword |
| aws_billing.cur.savings_plan.a_r_n |  | keyword |
| aws_billing.cur.savings_plan.amortized_upfront_commitment_for_billing_period |  | double |
| aws_billing.cur.savings_plan.effective_cost |  | double |
| aws_billing.cur.savings_plan.end_time |  | date |
| aws_billing.cur.savings_plan.instance_type_family |  | keyword |
| aws_billing.cur.savings_plan.net_amortized_upfront_commitment_for_billing_period |  | double |
| aws_billing.cur.savings_plan.net_effective_cost |  | double |
| aws_billing.cur.savings_plan.net_recurring_commitment_for_billing_period |  | double |
| aws_billing.cur.savings_plan.offering_type |  | keyword |
| aws_billing.cur.savings_plan.payment_option |  | keyword |
| aws_billing.cur.savings_plan.purchase_term |  | keyword |
| aws_billing.cur.savings_plan.rate |  | double |
| aws_billing.cur.savings_plan.recurring_commitment_for_billing_period |  | double |
| aws_billing.cur.savings_plan.region |  | keyword |
| aws_billing.cur.savings_plan.start_time |  | date |
| aws_billing.cur.savings_plan.total_commitment_to_date |  | double |
| aws_billing.cur.savings_plan.used_commitment |  | double |
| aws_billing.cur.total_discount |  | double |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| log.offset | Log offset | long |
