# ServiceNow

## Overview

[ServiceNow](https://www.servicenow.com/?state=seamless) is a cloud-based platform that helps organizations improve their workflows and business processes, mainly in IT service management. It offers features like workflow automation, a self-service portal for users, integration with other systems, and helpful reporting tools.

ServiceNow uses tables to store data, making it easy to manage and retrieve information. A key part of the platform is the [Configuration Management Database](https://www.servicenow.com/products/servicenow-platform/configuration-management-database.html) (CMDB), which keeps track of IT assets and how they are connected.

The ServiceNow integration can be used in three different modes to collect logs:
- **AWS S3 polling mode**: ServiceNow writes data to S3, and Elastic Agent polls the S3 bucket by listing its contents and reading new files. Refer to the [ServiceNow documentation](https://www.servicenow.com/community/now-platform-forum/aws-s3-integration-with-servicenow/td-p/1121852) for how to integrate AWS S3 with ServiceNow for retrieving logs into an S3 bucket.
- **AWS S3 SQS mode**: ServiceNow writes data to S3; S3 sends a notification of a new object to SQS; the Elastic Agent receives the notification from SQS and then reads the S3 object. Multiple agents can be used in this mode.
- **REST API mode**: ServiceNow offers table APIs to retrieve data from its tables; the Elastic Agent polls these APIs to list their contents and read any new data. Visit this [page](https://developer.servicenow.com/dev.do#!/reference/api/washingtondc/rest/c_TableAPI#table-GET) for additional information about REST APIs.

## Compatibility

This module has been tested with the latest(updated as of August 1, 2024) version of Xanadu on ServiceNow.

## Data streams

The ServiceNow integration supports both custom tables and default tables offered by ServiceNow. Additionally, both types of tables are included in the data stream labeled `event`.

This is the list of the default tables:

- `alm_hardware`
- `change_request`
- `change_task`
- `cmdb`
- `cmdb_ci`
- `cmdb_ci_app_server`
- `cmdb_ci_appl`
- `cmdb_ci_business_app`
- `cmdb_ci_computer`
- `cmdb_ci_db_instance`
- `cmdb_ci_esx_server`
- `cmdb_ci_hardware`
- `cmdb_ci_hyper_v_server`
- `cmdb_ci_infra_service`
- `cmdb_ci_linux_server`
- `cmdb_ci_server`
- `cmdb_ci_service`
- `cmdb_ci_vm`
- `cmdb_ci_win_server`
- `cmdb_rel_ci`
- `cmn_department`
- `cmn_location`
- `incident`
- `kb_knowledge`
- `problem`
- `sc_req_item`
- `sys_user`
- `sys_user_grmember`
- `sys_user_group`
- `task_ci`

**Note**:

1. This integration currently supports ECS mapping for default ServiceNow tables listed above. For custom tables created by users, ECS mapping is not automatically provided. If you want to add mappings for custom tables, please refer to this [tutorial guide](https://www.elastic.co/guide/en/fleet/current/data-streams-pipeline-tutorial.html).
2. A tag will be added to each table based on its name. For example, if logs are ingested from the `alm_hardware` table, users can view them in Discover by using the query `tags: "alm_hardware"`.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

### Collect logs through REST API

Your instance URL will serve as your base URL and will be formatted as follows: https://\<instance_id\>.service-now.com
Additionally, the username and password you use to log into your instance will be required to fetch logs in our integration.

### Collect logs through AWS S3

With an AWS S3 bucket that has been set up, you can configure it with ServiceNow by integrating it using your AWS S3 credentials.

### Collect logs through AWS SQS

1. Assuming you've already set up a connection to push data into the AWS bucket you can follow the steps below; if not, see the section above.
2. To set up an SQS queue, follow "Step 1: Create an Amazon SQS Queue" as described in the [Amazon S3 user guide](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
   - While creating an access policy, use the bucket name configured to create a connection for AWS S3 in ServiceNow.
3. Configure event notifications for an S3 bucket according to the [Amazon S3 user guide](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
   - While creating `event notification` select the event type as s3:ObjectCreated:*, destination type SQS Queue, and select the queue name created in Step 2.

### Time Zone Selection

In the Data Collection section, use the `Time Zone Offset` field to set your preferred timezone. The `.value` field for date data will always be in UTC, while the `.display_value` field can reflect your instance's selected timezone. The system default is set to America/Los_Angeles, but you can change this in your ServiceNow profile settings.

Follow these steps to See/Update the timezone in ServiceNow Instance:
1. Click the user icon in the top-right corner of the ServiceNow interface.
2. Select Profile from the dropdown menu.
3. In your Profile settings, locate the Timezone option.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **ServiceNow**.
3. Select the **ServiceNow** integration and add it.
4. While adding the integration, if you want to collect logs via REST API, then you have to put the following details:
   - collect logs via REST API toggled on
   - API URL
   - username
   - password
   - table name
   - timestamp field
   - timezone offset

   or if you want to collect logs via AWS S3, then you have to put the following details:
   - collect logs via S3 Bucket toggled on
   - access key id
   - secret access key
   - bucket arn
   - table name
   - timestamp field
   - timezone offset

   or if you want to collect logs via AWS SQS, then you have to put the following details:
   - collect logs via S3 Bucket toggled off
   - access key id
   - secret access key
   - queue url
   - table name
   - timestamp field
   - timezone offset
5. Save the integration.

**Note**: To fetch parquet file data, enable the toggle, `Parquet Codec`

## Troubleshooting

### Data Kind in S3

- By default, the integration expects the data in S3 to match with [ServiceNow REST API](https://developer.servicenow.com/dev.do#!/reference/api/washingtondc/rest/c_TableAPI#table-GET), i.e., each field as an object containing a `.value` and `.display_value` keys with their corresponding values. For more examples on sample events format, see [here](https://github.com/elastic/integrations/blob/main/packages/servicenow/data_stream/event/_dev/test/pipeline/test-event.log).
- If users are unable to store such key-value pairs of `.value` and `.display_value` inside S3 buckets, and the fields inside S3 buckets are scalars containing only `Display Values` of the fields, users can choose to enable the integration option `Data Has Only Display Values` under `Advanced options`. Instead, if the S3 buckets contain scalar fields with `Values` from each fields, users can disable this option. By default, the option is disabled.
- When the option `Data Has Only Display Values` is enabled, the ingest pipeline converts each scalar field to object by adding `.display_value`. For example, if this option is enabled, the S3 data `"install_status":"Installed"` is converted to `"install_status":{"display_value":"Installed"}` by the ingest pipeline. When this option is disabled, a similar S3 scalar form `"install_status":"Installed"` is converted to `"install_status":{"value":"Installed"}` by the ingest pipeline.
- This ensures proper parsing of ingest pipeline without causing mapping conflicts or processor failures.

## Logs Reference

### Event

This is the `Event` dataset.

#### Example

{{event "event"}}

{{fields "event"}}
