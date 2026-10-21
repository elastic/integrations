# AWS VPC Flow Logs FDS Assets

## Overview

This content pack installs a Kibana dashboard for [Amazon VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html) stored as Parquet in Amazon S3. Elasticsearch queries those objects in place through [ES|QL Data Federation](https://www.elastic.co/docs/reference/query-languages/esql/esql-data-federation). There is no Elastic Agent, ingest pipeline, or Elasticsearch index.

### Compatibility

* Elasticsearch 9.6.0 or later.
* Kibana 9.6.0 or later.

### How it works

The package registers no data collection. You register an S3 data source and a dataset yourself, then every dashboard panel queries the dataset with `FROM vpc_flow` using ES|QL Data Federation.

## What data does this integration collect?

The dashboard uses the default VPC Flow Logs version 2 fields: `start` (mapped to `@timestamp`), `action`, `srcaddr`, `dstaddr`, `srcport`, `dstport`, `protocol`, `packets`, `bytes`, and `interface_id`.

Extra version 3 through version 5 fields are safe to include in the flow log, but this dashboard does not chart them.

## What do I need to use this integration?

* [Cluster state encryption](https://www.elastic.co/docs/reference/elasticsearch/cluster-state-encryption-key) must be enabled. Elastic Cloud Hosted, Elastic Cloud Enterprise, ECK, Serverless, and fresh self-managed installs configure the encryption key automatically. Upgraded self-managed clusters require manual setup — follow the steps in the [cluster state encryption](https://www.elastic.co/docs/reference/elasticsearch/cluster-state-encryption-key) documentation.
* VPC Flow Logs published to S3 with both of the following settings:
  * Log file format **Parquet**. `.log.gz` has no FDS handler and returns 0 rows.
  * **Hive-compatible S3 prefixes** enabled. This creates `year=`, `month=`, and `day=` folders.
* An IAM identity with `s3:GetObject` and `s3:ListBucket` on the flow log bucket. For the full permissions reference, authentication models, and SSE-KMS setup, see [Amazon S3 data sources for ES|QL Data Federation](https://www.elastic.co/docs/reference/query-languages/esql/esql-data-federation-s3).

## How do I deploy this integration?

### Step 1. Configure AWS VPC Flow Logs

Skip this step if the flow log already publishes Parquet with Hive-compatible prefixes.

1. Open the Amazon VPC console and select **Your VPCs**, **Subnets**, or **Network interfaces**.
2. Select the resource, open the **Flow logs** tab, and choose **Create flow log**.
3. Set **Filter** to **All**, or to **Accept** or **Reject** if you only need one outcome. The dashboard expects both `ACCEPT` and `REJECT` when you want the rejected-traffic panels to be useful.
4. Set **Maximum aggregation interval** to 1 minute or 10 minutes.
5. Set **Destination** to **Send to an Amazon S3 bucket** and enter the bucket ARN.
6. Set **Log file format** to **Parquet**. Text `.log.gz` files are not supported.
7. Enable **Hive-compatible S3 prefixes**. This writes folders such as `aws-account-id=<ID>/aws-service=vpcflowlogs/aws-region=<region>/year=YYYY/month=MM/day=DD/`. Without that checkbox, partition detection cannot see the folders.
8. Leave the log record format at the default version 2 fields. Extra version 3 through version 5 fields are safe to include, but this dashboard does not chart them.
9. Create the flow log and copy the S3 location. New objects can take several minutes to appear.

If VPC Flow Logs are configured with **Partition logs by time → Every 1 hour**, add `hour=*/` to the resource glob and `hour(@timestamp)` to the `partition_spec`. See [Step 3](#step-3-register-the-vpc_flow-dataset).

### Step 2. Register the S3 data source

In Kibana Dev Tools, or with any Elasticsearch client:

```json
PUT _query/data_source/vpc_s3
{
  "type": "s3",
  "description": "VPC Flow Logs Parquet",
  "settings": {
    "region": "<REGION>",
    "access_key": "<ACCESS_KEY>",
    "secret_key": "<SECRET_KEY>"
  }
}
```

For all available settings, authentication models, and endpoint configuration, see [Data source settings reference](https://www.elastic.co/docs/reference/query-languages/esql/esql-data-federation-data-source-settings).

### Step 3. Register the vpc_flow dataset

The dataset name must be `vpc_flow`. Every data panel hardcodes `FROM vpc_flow`. To use another name you must edit each panel query after install.

**Daily partitions** (no hourly folders):

```json
PUT _query/dataset/vpc_flow
{
  "data_source": "vpc_s3",
  "resource": "s3://<BUCKET>/AWSLogs/aws-account-id=<ACCOUNT_ID>/aws-service=vpcflowlogs/aws-region=<REGION>/year=*/month=*/day=*/*.parquet",
  "settings": {
    "schema_resolution": "first_file_wins",
    "partition_detection": "hive",
    "partition_spec": "year(@timestamp), month(@timestamp), day(@timestamp), lag(@timestamp, 20m)"
  },
  "mappings": {
    "properties": {
      "@timestamp": { "type": "date", "path": "start", "format": "epoch_second" }
    }
  }
}
```

**Hourly partitions** (flow log configured with *Partition logs by time → Every 1 hour*):

```json
PUT _query/dataset/vpc_flow
{
  "data_source": "vpc_s3",
  "resource": "s3://<BUCKET>/AWSLogs/aws-account-id=<ACCOUNT_ID>/aws-service=vpcflowlogs/aws-region=<REGION>/year=*/month=*/day=*/hour=*/*.parquet",
  "settings": {
    "schema_resolution": "first_file_wins",
    "partition_detection": "hive",
    "partition_spec": "year(@timestamp), month(@timestamp), day(@timestamp), hour(@timestamp), lag(@timestamp, 20m)"
  },
  "mappings": {
    "properties": {
      "@timestamp": { "type": "date", "path": "start", "format": "epoch_second" }
    }
  }
}
```

Hourly partitioning gives finer-grained pruning — a 1-hour query scans one folder instead of a full day.

For a consolidated bucket, replace `aws-account-id=<ACCOUNT_ID>` and `aws-region=<REGION>` with `aws-account-id=*` and `aws-region=*`.

| Setting | Why it is set |
| --- | --- |
| `partition_spec` | Maps `year`, `month`, `day` (and optionally `hour`) folders onto `@timestamp` so queries only scan matching folders. |
| `lag(@timestamp, 20m)` | VPC Flow Logs often arrive 5–15 minutes late. Rows near midnight can land in the next day's folder. `lag` also lists that neighboring folder. |
| `@timestamp` mapping | Maps the `start` field (Unix seconds) to `@timestamp` so the time picker and `partition_spec` share one field. |

Confirm the registration:

```json
GET _query/dataset/vpc_flow
```

### Step 4. Install the dashboard

This package only installs Kibana assets. Register the data source and dataset before you open the dashboard.

1. In Kibana, open **Integrations**.
2. Search for **AWS VPC Flow Logs FDS Assets**.
3. Install the package. No agent policy is created.
4. Open **Analytics > Dashboards** and search for `[AWS VPC FDS] VPC Flow Logs Overview`. Assets are tagged **AWS**, **VPC Flow**, and **FDS**.

### Validation

Run a quick count in Dev Tools to confirm the dataset returns data:

```json
POST _query
{
  "query": "FROM vpc_flow | STATS total = COUNT(*)"
}
```

If the count returns `0`, verify the S3 path in the dataset resource glob matches the actual folder structure in the bucket.

## Troubleshooting

| Symptom | Cause | What to do |
| --- | --- | --- |
| `cluster state encryption is unavailable` | Self-managed cluster has no encryption key | Follow [cluster state encryption](https://www.elastic.co/docs/reference/elasticsearch/cluster-state-encryption-key) setup |
| Circuit breaker or out of memory | Heap is small, or too many FDS queries run at once | Narrow the date range or reduce concurrent viewers |
| Counts drop near midnight | Late files landed in the next day's folder | Keep `lag(@timestamp, 20m)` on `partition_spec` |

## Performance and scaling

Each dashboard load runs multiple queries against S3. A wide time range, or a missing `partition_spec`, increases the number of S3 requests. Auto-refresh keeps issuing those calls.

To reduce query cost:

* Always include `partition_spec` so Elasticsearch prunes folders outside the time range.
* Use hourly partitioning for finer-grained folder pruning.
* Narrow the dashboard time range rather than querying "Last 30 days".
* Avoid high-frequency auto-refresh intervals on broad time ranges.

## Limitations

* The dataset must be named `vpc_flow`, unless you edit every panel.
* Charts use version 2 fields only. `tcp-flags`, `vpc-id`, `subnet-id`, `instance-id`, and `flow-direction` are not visualized.
