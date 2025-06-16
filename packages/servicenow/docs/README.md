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

An example event for `event` looks as following:

```json
{
    "@timestamp": "2024-09-23T22:39:40.000-07:00",
    "agent": {
        "ephemeral_id": "c20cc9f6-33a8-49c0-ae00-d657b3bc2cbd",
        "id": "bee0774e-da2a-443a-b531-c0b608a56015",
        "name": "elastic-agent-27225",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "data_stream": {
        "dataset": "servicenow.event",
        "namespace": "34996",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "bee0774e-da2a-443a-b531-c0b608a56015",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "configuration",
            "threat"
        ],
        "created": "2016-12-12T15:19:57.000Z",
        "dataset": "servicenow.event",
        "id": "1c741bd70b2322007518478d83673af3",
        "ingested": "2025-06-03T09:44:57Z",
        "kind": "event",
        "severity": 3,
        "timezone": "America/Los_Angeles",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "user": [
            "David Loo",
            "Joe Employee",
            "employee",
            "admin"
        ]
    },
    "servicenow": {
        "event": {
            "activity_due": {
                "display_value": "2016-12-12T17:26:36.000-08:00",
                "value": "2016-12-13T01:26:36.000Z"
            },
            "assigned_to": {
                "display_value": "David Loo",
                "value": "5137153cc611227c000bbd1bd8cd2007"
            },
            "closed_at": {
                "display_value": "2016-12-13T18:46:44.000-08:00",
                "value": "2016-12-14T02:46:44.000Z"
            },
            "opened_at": {
                "display_value": "2016-12-12T07:19:57.000-08:00",
                "value": "2016-12-12T15:19:57.000Z"
            },
            "opened_by": {
                "value": "681ccaf9c0a8016400b98a06818d57c7"
            },
            "priority": {
                "display_value": "3 - Moderate",
                "value": 3
            },
            "severity": {
                "display_value": "3 - Low"
            },
            "state": {
                "display_value": "Closed",
                "value": "7"
            },
            "sys_created_by": {
                "display_value": "employee",
                "value": "employee"
            },
            "sys_created_on": {
                "display_value": "2016-12-12T07:19:57.000-08:00"
            },
            "sys_domain": {
                "display_value": "global",
                "value": "global"
            },
            "sys_domain_path": {
                "display_value": "/",
                "value": "/"
            },
            "sys_id": {
                "value": "1c741bd70b2322007518478d83673af3"
            },
            "sys_updated_by": {
                "display_value": "admin",
                "value": "admin"
            },
            "sys_updated_on": {
                "display_value": "2024-09-23T22:39:40.000-07:00",
                "value": "2024-09-24T05:39:40.000Z"
            },
            "table_name": "incident"
        }
    },
    "tags": [
        "incident",
        "hide_sensitive",
        "forwarded",
        "servicenow-event"
    ],
    "user": {
        "name": "Joe Employee"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| servicenow.event.acquisition_method.display_value |  | keyword |
| servicenow.event.acquisition_method.value |  | keyword |
| servicenow.event.active.display_value |  | boolean |
| servicenow.event.active.value |  | boolean |
| servicenow.event.active_user_count.display_value |  | keyword |
| servicenow.event.active_user_count.value |  | long |
| servicenow.event.activity_due.display_value |  | date |
| servicenow.event.activity_due.value |  | date |
| servicenow.event.added_from_dynamic_ci.display_value |  | keyword |
| servicenow.event.added_from_dynamic_ci.value |  | keyword |
| servicenow.event.additional_assignee_list.display_value |  | keyword |
| servicenow.event.additional_assignee_list.value |  | keyword |
| servicenow.event.age.display_value |  | keyword |
| servicenow.event.age.value |  | keyword |
| servicenow.event.age_in_month.display_value |  | keyword |
| servicenow.event.age_in_month.value |  | keyword |
| servicenow.event.aliases.display_value |  | keyword |
| servicenow.event.aliases.value |  | keyword |
| servicenow.event.allotted_electric_power.display_value |  | keyword |
| servicenow.event.allotted_electric_power.value |  | keyword |
| servicenow.event.allotted_electric_power_unit.display_value |  | keyword |
| servicenow.event.allotted_electric_power_unit.value |  | keyword |
| servicenow.event.apm_business_process.display_value |  | keyword |
| servicenow.event.apm_business_process.value |  | keyword |
| servicenow.event.application_manager.display_value |  | keyword |
| servicenow.event.application_manager.value |  | keyword |
| servicenow.event.application_type.display_value |  | keyword |
| servicenow.event.application_type.value |  | keyword |
| servicenow.event.applied.display_value |  | boolean |
| servicenow.event.applied.value |  | boolean |
| servicenow.event.applied_date.display_value |  | date |
| servicenow.event.applied_date.value |  | date |
| servicenow.event.appraisal_fiscal_type.display_value |  | keyword |
| servicenow.event.appraisal_fiscal_type.value |  | keyword |
| servicenow.event.approval.display_value |  | keyword |
| servicenow.event.approval.value |  | keyword |
| servicenow.event.approval_history.display_value |  | keyword |
| servicenow.event.approval_history.value |  | keyword |
| servicenow.event.approval_set.display_value |  | date |
| servicenow.event.approval_set.value |  | date |
| servicenow.event.architecture_type.display_value |  | keyword |
| servicenow.event.architecture_type.value |  | keyword |
| servicenow.event.article_type.display_value |  | keyword |
| servicenow.event.article_type.value |  | keyword |
| servicenow.event.asset.display_value |  | keyword |
| servicenow.event.asset.value |  | keyword |
| servicenow.event.asset_function.display_value |  | keyword |
| servicenow.event.asset_function.value |  | keyword |
| servicenow.event.asset_tag.display_value |  | keyword |
| servicenow.event.asset_tag.value |  | keyword |
| servicenow.event.assigned.display_value |  | date |
| servicenow.event.assigned.value |  | date |
| servicenow.event.assigned_to.display_value |  | keyword |
| servicenow.event.assigned_to.value |  | keyword |
| servicenow.event.assignment_group.display_value |  | keyword |
| servicenow.event.assignment_group.value |  | keyword |
| servicenow.event.attestation_score.display_value |  | keyword |
| servicenow.event.attestation_score.value |  | long |
| servicenow.event.attestation_status.display_value |  | keyword |
| servicenow.event.attestation_status.value |  | keyword |
| servicenow.event.attested.display_value |  | boolean |
| servicenow.event.attested.value |  | boolean |
| servicenow.event.attested_by.display_value |  | keyword |
| servicenow.event.attested_by.value |  | keyword |
| servicenow.event.attested_date.display_value |  | date |
| servicenow.event.attested_date.value |  | date |
| servicenow.event.attributes.display_value |  | keyword |
| servicenow.event.attributes.value |  | keyword |
| servicenow.event.audience_type.display_value |  | keyword |
| servicenow.event.audience_type.value |  | keyword |
| servicenow.event.author.display_value |  | keyword |
| servicenow.event.author.value |  | keyword |
| servicenow.event.avatar.display_value |  | keyword |
| servicenow.event.avatar.value |  | keyword |
| servicenow.event.backordered.display_value |  | boolean |
| servicenow.event.backordered.value |  | boolean |
| servicenow.event.backout_plan.display_value |  | keyword |
| servicenow.event.backout_plan.value |  | keyword |
| servicenow.event.beneficiary.display_value |  | keyword |
| servicenow.event.beneficiary.value |  | keyword |
| servicenow.event.billable.display_value |  | boolean |
| servicenow.event.billable.value |  | boolean |
| servicenow.event.building.display_value |  | keyword |
| servicenow.event.building.value |  | keyword |
| servicenow.event.busines_criticality.display_value |  | keyword |
| servicenow.event.busines_criticality.value |  | keyword |
| servicenow.event.business_contact.display_value |  | keyword |
| servicenow.event.business_contact.value |  | keyword |
| servicenow.event.business_criticality.display_value |  | keyword |
| servicenow.event.business_criticality.text_value |  | keyword |
| servicenow.event.business_criticality.value |  | long |
| servicenow.event.business_duration.display_value |  | keyword |
| servicenow.event.business_duration.value |  | date |
| servicenow.event.business_impact.display_value |  | keyword |
| servicenow.event.business_impact.value |  | keyword |
| servicenow.event.business_need.display_value |  | keyword |
| servicenow.event.business_need.value |  | keyword |
| servicenow.event.business_relation_manager.display_value |  | keyword |
| servicenow.event.business_relation_manager.value |  | keyword |
| servicenow.event.business_service.display_value |  | keyword |
| servicenow.event.business_service.value |  | keyword |
| servicenow.event.business_stc.display_value |  | keyword |
| servicenow.event.business_stc.value |  | long |
| servicenow.event.business_unit.display_value |  | keyword |
| servicenow.event.business_unit.value |  | keyword |
| servicenow.event.cab_date_time.display_value |  | date |
| servicenow.event.cab_date_time.value |  | date |
| servicenow.event.cab_delegate.display_value |  | keyword |
| servicenow.event.cab_delegate.value |  | keyword |
| servicenow.event.cab_recommendation.display_value |  | keyword |
| servicenow.event.cab_recommendation.value |  | keyword |
| servicenow.event.cab_required.display_value |  | boolean |
| servicenow.event.cab_required.value |  | boolean |
| servicenow.event.calendar_duration.display_value |  | keyword |
| servicenow.event.calendar_duration.value |  | date |
| servicenow.event.calendar_integration.display_value |  | keyword |
| servicenow.event.calendar_integration.value |  | long |
| servicenow.event.calendar_stc.display_value |  | keyword |
| servicenow.event.calendar_stc.value |  | long |
| servicenow.event.caller_id.display_value |  | keyword |
| servicenow.event.caller_id.value |  | keyword |
| servicenow.event.can_print.display_value |  | boolean |
| servicenow.event.can_print.value |  | boolean |
| servicenow.event.can_read_user_criteria.display_value |  | keyword |
| servicenow.event.can_read_user_criteria.value |  | keyword |
| servicenow.event.cannot_read_user_criteria.display_value |  | keyword |
| servicenow.event.cannot_read_user_criteria.value |  | keyword |
| servicenow.event.cat_item.display_value |  | keyword |
| servicenow.event.cat_item.value |  | keyword |
| servicenow.event.category.display_value |  | keyword |
| servicenow.event.category.value |  | keyword |
| servicenow.event.cause.display_value |  | keyword |
| servicenow.event.cause.value |  | keyword |
| servicenow.event.cause_notes.display_value |  | keyword |
| servicenow.event.cause_notes.value |  | keyword |
| servicenow.event.caused_by.display_value |  | keyword |
| servicenow.event.caused_by.value |  | keyword |
| servicenow.event.cd_rom.display_value |  | boolean |
| servicenow.event.cd_rom.value |  | boolean |
| servicenow.event.cd_speed.display_value |  | keyword |
| servicenow.event.cd_speed.value |  | double |
| servicenow.event.certified.display_value |  | boolean |
| servicenow.event.certified.value |  | boolean |
| servicenow.event.change_control.display_value |  | keyword |
| servicenow.event.change_control.value |  | keyword |
| servicenow.event.change_plan.display_value |  | keyword |
| servicenow.event.change_plan.value |  | keyword |
| servicenow.event.change_request.display_value |  | keyword |
| servicenow.event.change_request.value |  | keyword |
| servicenow.event.change_task_type.display_value |  | keyword |
| servicenow.event.change_task_type.value |  | keyword |
| servicenow.event.chassis_type.display_value |  | keyword |
| servicenow.event.chassis_type.value |  | keyword |
| servicenow.event.checked_in.display_value |  | date |
| servicenow.event.checked_in.value |  | date |
| servicenow.event.checked_out.display_value |  | date |
| servicenow.event.checked_out.value |  | date |
| servicenow.event.checkout.display_value |  | keyword |
| servicenow.event.checkout.value |  | keyword |
| servicenow.event.chg_model.display_value |  | keyword |
| servicenow.event.chg_model.value |  | keyword |
| servicenow.event.child.display_value |  | keyword |
| servicenow.event.child.value |  | keyword |
| servicenow.event.child_incidents.display_value |  | keyword |
| servicenow.event.child_incidents.value |  | long |
| servicenow.event.ci.display_value |  | keyword |
| servicenow.event.ci.value |  | keyword |
| servicenow.event.ci_item.display_value |  | keyword |
| servicenow.event.ci_item.value |  | keyword |
| servicenow.event.city.display_value |  | keyword |
| servicenow.event.city.value |  | keyword |
| servicenow.event.cl_port.display_value |  | keyword |
| servicenow.event.cl_port.value |  | long |
| servicenow.event.classification.display_value |  | keyword |
| servicenow.event.classification.value |  | keyword |
| servicenow.event.classifier.display_value |  | keyword |
| servicenow.event.classifier.value |  | keyword |
| servicenow.event.close_code.display_value |  | keyword |
| servicenow.event.close_code.value |  | keyword |
| servicenow.event.close_notes.display_value |  | keyword |
| servicenow.event.close_notes.value |  | keyword |
| servicenow.event.closed_at.display_value |  | date |
| servicenow.event.closed_at.value |  | date |
| servicenow.event.closed_by.display_value |  | keyword |
| servicenow.event.closed_by.value |  | keyword |
| servicenow.event.cluster_id.display_value |  | keyword |
| servicenow.event.cluster_id.value |  | keyword |
| servicenow.event.cluster_name.display_value |  | keyword |
| servicenow.event.cluster_name.value |  | keyword |
| servicenow.event.cmdb_ci.display_value |  | keyword |
| servicenow.event.cmdb_ci.value |  | keyword |
| servicenow.event.cmdb_ot_entity.display_value |  | keyword |
| servicenow.event.cmdb_ot_entity.value |  | keyword |
| servicenow.event.cmdb_software_product_model.display_value |  | keyword |
| servicenow.event.cmdb_software_product_model.value |  | keyword |
| servicenow.event.cmn_location_source.display_value |  | keyword |
| servicenow.event.cmn_location_source.value |  | keyword |
| servicenow.event.cmn_location_type.display_value |  | keyword |
| servicenow.event.cmn_location_type.value |  | keyword |
| servicenow.event.comments.display_value |  | keyword |
| servicenow.event.comments.value |  | keyword |
| servicenow.event.comments_and_work_notes.display_value |  | keyword |
| servicenow.event.comments_and_work_notes.value |  | keyword |
| servicenow.event.company.display_value |  | keyword |
| servicenow.event.company.value |  | keyword |
| servicenow.event.compatibility_dependencies.display_value |  | keyword |
| servicenow.event.compatibility_dependencies.value |  | keyword |
| servicenow.event.config_directory.display_value |  | keyword |
| servicenow.event.config_directory.value |  | keyword |
| servicenow.event.config_file.display_value |  | keyword |
| servicenow.event.config_file.value |  | keyword |
| servicenow.event.configuration_item.display_value |  | keyword |
| servicenow.event.configuration_item.value |  | keyword |
| servicenow.event.confirmed_at.display_value |  | date |
| servicenow.event.confirmed_at.value |  | date |
| servicenow.event.confirmed_by.display_value |  | keyword |
| servicenow.event.confirmed_by.value |  | keyword |
| servicenow.event.conflict_last_run.display_value |  | date |
| servicenow.event.conflict_last_run.value |  | date |
| servicenow.event.conflict_status.display_value |  | keyword |
| servicenow.event.conflict_status.value |  | keyword |
| servicenow.event.connection_state.display_value |  | keyword |
| servicenow.event.connection_state.value |  | keyword |
| servicenow.event.connection_strength.display_value |  | keyword |
| servicenow.event.connection_strength.value |  | keyword |
| servicenow.event.consumer_type.display_value |  | keyword |
| servicenow.event.consumer_type.value |  | keyword |
| servicenow.event.contact.display_value |  | keyword |
| servicenow.event.contact.value |  | keyword |
| servicenow.event.contact_type.display_value |  | keyword |
| servicenow.event.contact_type.value |  | keyword |
| servicenow.event.container.display_value |  | keyword |
| servicenow.event.container.value |  | keyword |
| servicenow.event.context.display_value |  | keyword |
| servicenow.event.context.value |  | keyword |
| servicenow.event.contract.display_value |  | keyword |
| servicenow.event.contract.value |  | keyword |
| servicenow.event.contract_end_date.display_value |  | date |
| servicenow.event.contract_end_date.value |  | date |
| servicenow.event.coordinates_retrieved_on.display_value |  | date |
| servicenow.event.coordinates_retrieved_on.value |  | date |
| servicenow.event.correlation_display.display_value |  | keyword |
| servicenow.event.correlation_display.value |  | keyword |
| servicenow.event.correlation_id.display_value |  | keyword |
| servicenow.event.correlation_id.value |  | keyword |
| servicenow.event.cost.currency_display_value |  | keyword |
| servicenow.event.cost.display_value |  | keyword |
| servicenow.event.cost.value |  | double |
| servicenow.event.cost_cc.display_value |  | keyword |
| servicenow.event.cost_cc.value |  | keyword |
| servicenow.event.cost_center.display_value |  | keyword |
| servicenow.event.cost_center.value |  | keyword |
| servicenow.event.country.display_value |  | keyword |
| servicenow.event.country.value |  | keyword |
| servicenow.event.cpu_core_count.display_value |  | keyword |
| servicenow.event.cpu_core_count.value |  | long |
| servicenow.event.cpu_core_thread.display_value |  | keyword |
| servicenow.event.cpu_core_thread.value |  | long |
| servicenow.event.cpu_count.display_value |  | keyword |
| servicenow.event.cpu_count.value |  | long |
| servicenow.event.cpu_manufacturer.display_value |  | keyword |
| servicenow.event.cpu_manufacturer.value |  | keyword |
| servicenow.event.cpu_name.display_value |  | keyword |
| servicenow.event.cpu_name.value |  | keyword |
| servicenow.event.cpu_speed.display_value |  | keyword |
| servicenow.event.cpu_speed.value |  | double |
| servicenow.event.cpu_type.display_value |  | keyword |
| servicenow.event.cpu_type.value |  | keyword |
| servicenow.event.created_from.display_value |  | keyword |
| servicenow.event.created_from.value |  | keyword |
| servicenow.event.currency.display_value |  | keyword |
| servicenow.event.currency.value |  | keyword |
| servicenow.event.data_classification.display_value |  | keyword |
| servicenow.event.data_classification.value |  | keyword |
| servicenow.event.date_format.display_value |  | keyword |
| servicenow.event.date_format.value |  | keyword |
| servicenow.event.default_assignee.display_value |  | keyword |
| servicenow.event.default_assignee.value |  | keyword |
| servicenow.event.default_gateway.display_value |  | keyword |
| servicenow.event.default_gateway.value |  | keyword |
| servicenow.event.default_perspective.display_value |  | keyword |
| servicenow.event.default_perspective.value |  | keyword |
| servicenow.event.delivery_date.display_value |  | date |
| servicenow.event.delivery_date.value |  | date |
| servicenow.event.delivery_manager.display_value |  | keyword |
| servicenow.event.delivery_manager.value |  | keyword |
| servicenow.event.delivery_plan.display_value |  | keyword |
| servicenow.event.delivery_plan.value |  | keyword |
| servicenow.event.delivery_task.display_value |  | keyword |
| servicenow.event.delivery_task.value |  | keyword |
| servicenow.event.department.display_value |  | keyword |
| servicenow.event.department.value |  | keyword |
| servicenow.event.depreciated_amount.currency_display_value |  | keyword |
| servicenow.event.depreciated_amount.display_value |  | keyword |
| servicenow.event.depreciated_amount.value |  | double |
| servicenow.event.depreciation.display_value |  | keyword |
| servicenow.event.depreciation.value |  | keyword |
| servicenow.event.depreciation_date.display_value |  | date |
| servicenow.event.depreciation_date.value |  | date |
| servicenow.event.dept_head.display_value |  | keyword |
| servicenow.event.dept_head.value |  | keyword |
| servicenow.event.description.display_value |  | keyword |
| servicenow.event.description.value |  | keyword |
| servicenow.event.direct.display_value |  | boolean |
| servicenow.event.direct.value |  | boolean |
| servicenow.event.disable_commenting.display_value |  | boolean |
| servicenow.event.disable_commenting.value |  | boolean |
| servicenow.event.disable_suggesting.display_value |  | boolean |
| servicenow.event.disable_suggesting.value |  | boolean |
| servicenow.event.discovery_source.display_value |  | keyword |
| servicenow.event.discovery_source.value |  | keyword |
| servicenow.event.disk_space.display_value |  | keyword |
| servicenow.event.disk_space.value |  | double |
| servicenow.event.display_attachments.display_value |  | boolean |
| servicenow.event.display_attachments.value |  | boolean |
| servicenow.event.display_name.display_value |  | keyword |
| servicenow.event.display_name.value |  | keyword |
| servicenow.event.disposal_reason.display_value |  | keyword |
| servicenow.event.disposal_reason.value |  | keyword |
| servicenow.event.dns_domain.display_value |  | keyword |
| servicenow.event.dns_domain.value |  | keyword |
| servicenow.event.dr_backup.display_value |  | keyword |
| servicenow.event.dr_backup.value |  | keyword |
| servicenow.event.due.display_value |  | date |
| servicenow.event.due.value |  | date |
| servicenow.event.due_date.display_value |  | date |
| servicenow.event.due_date.value |  | date |
| servicenow.event.due_in.display_value |  | keyword |
| servicenow.event.due_in.value |  | keyword |
| servicenow.event.duplicate.display_value |  | boolean |
| servicenow.event.duplicate.value |  | boolean |
| servicenow.event.duplicate_of.display_value |  | keyword |
| servicenow.event.duplicate_of.value |  | keyword |
| servicenow.event.edition.display_value |  | keyword |
| servicenow.event.edition.value |  | keyword |
| servicenow.event.eligible_for_refresh.display_value |  | boolean |
| servicenow.event.eligible_for_refresh.value |  | boolean |
| servicenow.event.email.display_value |  | keyword |
| servicenow.event.email.value |  | keyword |
| servicenow.event.emergency_tier.display_value |  | keyword |
| servicenow.event.emergency_tier.value |  | keyword |
| servicenow.event.employee_number.display_value |  | keyword |
| servicenow.event.employee_number.value |  | keyword |
| servicenow.event.enable_multifactor_authn.display_value |  | boolean |
| servicenow.event.enable_multifactor_authn.value |  | boolean |
| servicenow.event.end_date.display_value |  | date |
| servicenow.event.end_date.value |  | date |
| servicenow.event.environment.display_value |  | keyword |
| servicenow.event.environment.value |  | keyword |
| servicenow.event.escalation.display_value |  | keyword |
| servicenow.event.escalation.value |  | long |
| servicenow.event.estimated_delivery.display_value |  | date |
| servicenow.event.estimated_delivery.value |  | date |
| servicenow.event.exclude_manager.display_value |  | boolean |
| servicenow.event.exclude_manager.value |  | boolean |
| servicenow.event.expected_start.display_value |  | date |
| servicenow.event.expected_start.value |  | date |
| servicenow.event.expenditure_type.display_value |  | keyword |
| servicenow.event.expenditure_type.value |  | keyword |
| servicenow.event.failed_attempts.display_value |  | keyword |
| servicenow.event.failed_attempts.value |  | long |
| servicenow.event.fault_count.display_value |  | keyword |
| servicenow.event.fault_count.value |  | long |
| servicenow.event.fax_phone.display_value |  | keyword |
| servicenow.event.fax_phone.value |  | keyword |
| servicenow.event.federated_id.display_value |  | keyword |
| servicenow.event.federated_id.value |  | keyword |
| servicenow.event.firewall_status.display_value |  | keyword |
| servicenow.event.firewall_status.value |  | keyword |
| servicenow.event.first_discovered.display_value |  | date |
| servicenow.event.first_discovered.value |  | date |
| servicenow.event.first_name.display_value |  | keyword |
| servicenow.event.first_name.value |  | keyword |
| servicenow.event.first_reported_by_task.display_value |  | keyword |
| servicenow.event.first_reported_by_task.value |  | keyword |
| servicenow.event.fix_at.display_value |  | date |
| servicenow.event.fix_at.value |  | date |
| servicenow.event.fix_by.display_value |  | keyword |
| servicenow.event.fix_by.value |  | keyword |
| servicenow.event.fix_communicated_at.display_value |  | date |
| servicenow.event.fix_communicated_at.value |  | date |
| servicenow.event.fix_communicated_by.display_value |  | keyword |
| servicenow.event.fix_communicated_by.value |  | keyword |
| servicenow.event.fix_notes.display_value |  | keyword |
| servicenow.event.fix_notes.value |  | keyword |
| servicenow.event.flagged.display_value |  | boolean |
| servicenow.event.flagged.value |  | boolean |
| servicenow.event.floppy.display_value |  | keyword |
| servicenow.event.floppy.value |  | keyword |
| servicenow.event.flow_context.display_value |  | keyword |
| servicenow.event.flow_context.value |  | keyword |
| servicenow.event.follow_up.display_value |  | date |
| servicenow.event.follow_up.value |  | date |
| servicenow.event.form_factor.display_value |  | keyword |
| servicenow.event.form_factor.value |  | keyword |
| servicenow.event.fqdn.display_value |  | keyword |
| servicenow.event.fqdn.value |  | keyword |
| servicenow.event.full_name.display_value |  | keyword |
| servicenow.event.full_name.value |  | keyword |
| servicenow.event.gender.display_value |  | keyword |
| servicenow.event.gender.value |  | keyword |
| servicenow.event.generated_with_now_assist.display_value |  | boolean |
| servicenow.event.generated_with_now_assist.value |  | boolean |
| servicenow.event.gl_account.display_value |  | keyword |
| servicenow.event.gl_account.value |  | keyword |
| servicenow.event.group.display_value |  | keyword |
| servicenow.event.group.value |  | keyword |
| servicenow.event.group_list.display_value |  | keyword |
| servicenow.event.group_list.value |  | keyword |
| servicenow.event.hardware_status.display_value |  | keyword |
| servicenow.event.hardware_status.value |  | keyword |
| servicenow.event.hardware_substatus.display_value |  | keyword |
| servicenow.event.hardware_substatus.value |  | keyword |
| servicenow.event.head_count.display_value |  | keyword |
| servicenow.event.head_count.value |  | long |
| servicenow.event.helpful_count.display_value |  | keyword |
| servicenow.event.helpful_count.value |  | keyword |
| servicenow.event.hold_reason.display_value |  | keyword |
| servicenow.event.hold_reason.value |  | keyword |
| servicenow.event.home_phone.display_value |  | keyword |
| servicenow.event.home_phone.value |  | keyword |
| servicenow.event.host_name.display_value |  | keyword |
| servicenow.event.host_name.value |  | keyword |
| servicenow.event.hyper_threading.display_value |  | boolean |
| servicenow.event.hyper_threading.value |  | boolean |
| servicenow.event.id.display_value |  | keyword |
| servicenow.event.id.value |  | keyword |
| servicenow.event.image.display_value |  | keyword |
| servicenow.event.image.value |  | keyword |
| servicenow.event.impact.display_value |  | keyword |
| servicenow.event.impact.value |  | long |
| servicenow.event.implementation_plan.display_value |  | keyword |
| servicenow.event.implementation_plan.value |  | keyword |
| servicenow.event.incident_state.display_value |  | keyword |
| servicenow.event.incident_state.value |  | long |
| servicenow.event.include_members.display_value |  | boolean |
| servicenow.event.include_members.value |  | boolean |
| servicenow.event.install_date.display_value |  | date |
| servicenow.event.install_date.value |  | date |
| servicenow.event.install_directory.display_value |  | keyword |
| servicenow.event.install_directory.value |  | keyword |
| servicenow.event.install_status.display_value |  | keyword |
| servicenow.event.install_status.value |  | long |
| servicenow.event.install_type.display_value |  | keyword |
| servicenow.event.install_type.value |  | keyword |
| servicenow.event.instrumentation_metadata.display_value |  | keyword |
| servicenow.event.instrumentation_metadata.value |  | keyword |
| servicenow.event.internal_integration_user.display_value |  | boolean |
| servicenow.event.internal_integration_user.value |  | boolean |
| servicenow.event.internet_facing.display_value |  | boolean |
| servicenow.event.internet_facing.value |  | boolean |
| servicenow.event.introduction.display_value |  | keyword |
| servicenow.event.introduction.value |  | keyword |
| servicenow.event.invoice_number.display_value |  | keyword |
| servicenow.event.invoice_number.value |  | keyword |
| servicenow.event.ip_address.display_value |  | ip |
| servicenow.event.ip_address.value |  | ip |
| servicenow.event.is_clustered.display_value |  | boolean |
| servicenow.event.is_clustered.value |  | boolean |
| servicenow.event.it_application_owner.display_value |  | keyword |
| servicenow.event.it_application_owner.value |  | keyword |
| servicenow.event.justification.display_value |  | keyword |
| servicenow.event.justification.value |  | keyword |
| servicenow.event.kb_category.display_value |  | keyword |
| servicenow.event.kb_category.value |  | keyword |
| servicenow.event.kb_knowledge_base.display_value |  | keyword |
| servicenow.event.kb_knowledge_base.value |  | keyword |
| servicenow.event.kernel_release.display_value |  | keyword |
| servicenow.event.kernel_release.value |  | keyword |
| servicenow.event.knowledge.display_value |  | boolean |
| servicenow.event.knowledge.value |  | boolean |
| servicenow.event.known_error.display_value |  | boolean |
| servicenow.event.known_error.value |  | boolean |
| servicenow.event.last_change_date.display_value |  | keyword |
| servicenow.event.last_change_date.value |  | keyword |
| servicenow.event.last_discovered.display_value |  | date |
| servicenow.event.last_discovered.value |  | date |
| servicenow.event.last_login.display_value |  | date |
| servicenow.event.last_login.value |  | date |
| servicenow.event.last_login_time.display_value |  | date |
| servicenow.event.last_login_time.value |  | date |
| servicenow.event.last_name.display_value |  | keyword |
| servicenow.event.last_name.value |  | keyword |
| servicenow.event.last_review_date.display_value |  | date |
| servicenow.event.last_review_date.value |  | date |
| servicenow.event.lat_long_error.display_value |  | keyword |
| servicenow.event.lat_long_error.value |  | keyword |
| servicenow.event.latitude.display_value |  | double |
| servicenow.event.latitude.value |  | double |
| servicenow.event.ldap_server.display_value |  | keyword |
| servicenow.event.ldap_server.value |  | keyword |
| servicenow.event.lease_id.display_value |  | keyword |
| servicenow.event.lease_id.value |  | keyword |
| servicenow.event.life_cycle_stage.display_value |  | keyword |
| servicenow.event.life_cycle_stage.value |  | keyword |
| servicenow.event.life_cycle_stage_status.display_value |  | keyword |
| servicenow.event.life_cycle_stage_status.value |  | keyword |
| servicenow.event.listener_name.display_value |  | keyword |
| servicenow.event.listener_name.value |  | keyword |
| servicenow.event.location.display_value |  | keyword |
| servicenow.event.location.value |  | keyword |
| servicenow.event.locked_out.display_value |  | boolean |
| servicenow.event.locked_out.value |  | boolean |
| servicenow.event.logical_processor.display_value |  | keyword |
| servicenow.event.logical_processor.value |  | keyword |
| servicenow.event.longitude.display_value |  | double |
| servicenow.event.longitude.value |  | double |
| servicenow.event.mac_address.display_value |  | keyword |
| servicenow.event.mac_address.value |  | keyword |
| servicenow.event.made_sla.display_value |  | boolean |
| servicenow.event.made_sla.value |  | boolean |
| servicenow.event.maintenance_schedule.display_value |  | keyword |
| servicenow.event.maintenance_schedule.value |  | keyword |
| servicenow.event.major_problem.display_value |  | boolean |
| servicenow.event.major_problem.value |  | boolean |
| servicenow.event.managed_by.display_value |  | keyword |
| servicenow.event.managed_by.value |  | keyword |
| servicenow.event.managed_by_group.display_value |  | keyword |
| servicenow.event.managed_by_group.value |  | keyword |
| servicenow.event.manager.display_value |  | keyword |
| servicenow.event.manager.value |  | keyword |
| servicenow.event.manual_proposed_change.display_value |  | boolean |
| servicenow.event.manual_proposed_change.value |  | boolean |
| servicenow.event.manufacturer.display_value |  | keyword |
| servicenow.event.manufacturer.value |  | keyword |
| servicenow.event.meta.display_value |  | keyword |
| servicenow.event.meta.value |  | keyword |
| servicenow.event.meta_description.display_value |  | keyword |
| servicenow.event.meta_description.value |  | keyword |
| servicenow.event.metric_type.display_value |  | keyword |
| servicenow.event.metric_type.value |  | keyword |
| servicenow.event.middle_name.display_value |  | keyword |
| servicenow.event.middle_name.value |  | keyword |
| servicenow.event.mobile_phone.display_value |  | keyword |
| servicenow.event.mobile_phone.value |  | keyword |
| servicenow.event.model.display_value |  | keyword |
| servicenow.event.model.value |  | keyword |
| servicenow.event.model_category.display_value |  | keyword |
| servicenow.event.model_category.value |  | keyword |
| servicenow.event.model_component.display_value |  | keyword |
| servicenow.event.model_component.value |  | keyword |
| servicenow.event.model_component_id.display_value |  | keyword |
| servicenow.event.model_component_id.value |  | keyword |
| servicenow.event.model_id.display_value |  | keyword |
| servicenow.event.model_id.value |  | keyword |
| servicenow.event.model_number.display_value |  | keyword |
| servicenow.event.model_number.value |  | keyword |
| servicenow.event.monitor.display_value |  | boolean |
| servicenow.event.monitor.value |  | boolean |
| servicenow.event.monitoring_requirements.display_value |  | keyword |
| servicenow.event.monitoring_requirements.value |  | keyword |
| servicenow.event.morid.display_value |  | keyword |
| servicenow.event.morid.value |  | keyword |
| servicenow.event.most_frequent_user.display_value |  | keyword |
| servicenow.event.most_frequent_user.value |  | keyword |
| servicenow.event.name.display_value |  | keyword |
| servicenow.event.name.value |  | keyword |
| servicenow.event.next_assessment_date.display_value |  | date |
| servicenow.event.next_assessment_date.value |  | date |
| servicenow.event.notification.display_value |  | keyword |
| servicenow.event.notification.value |  | long |
| servicenow.event.notify.display_value |  | keyword |
| servicenow.event.notify.value |  | long |
| servicenow.event.number.display_value |  | keyword |
| servicenow.event.number.value |  | keyword |
| servicenow.event.object_id.display_value |  | keyword |
| servicenow.event.object_id.value |  | keyword |
| servicenow.event.old_status.display_value |  | keyword |
| servicenow.event.old_status.value |  | keyword |
| servicenow.event.old_substatus.display_value |  | keyword |
| servicenow.event.old_substatus.value |  | keyword |
| servicenow.event.on_hold.display_value |  | boolean |
| servicenow.event.on_hold.value |  | boolean |
| servicenow.event.on_hold_reason.display_value |  | keyword |
| servicenow.event.on_hold_reason.value |  | keyword |
| servicenow.event.on_hold_task.display_value |  | keyword |
| servicenow.event.on_hold_task.value |  | keyword |
| servicenow.event.opened_at.display_value |  | date |
| servicenow.event.opened_at.value |  | date |
| servicenow.event.opened_by.display_value |  | keyword |
| servicenow.event.opened_by.value |  | keyword |
| servicenow.event.operational_status.display_value |  | keyword |
| servicenow.event.operational_status.value |  | long |
| servicenow.event.order.display_value |  | keyword |
| servicenow.event.order.value |  | long |
| servicenow.event.order_date.display_value |  | date |
| servicenow.event.order_date.value |  | date |
| servicenow.event.order_guide.display_value |  | keyword |
| servicenow.event.order_guide.value |  | keyword |
| servicenow.event.organization_unit_count.display_value |  | keyword |
| servicenow.event.organization_unit_count.value |  | long |
| servicenow.event.origin_id.display_value |  | keyword |
| servicenow.event.origin_id.value |  | keyword |
| servicenow.event.origin_table.display_value |  | keyword |
| servicenow.event.origin_table.value |  | keyword |
| servicenow.event.os.display_value |  | keyword |
| servicenow.event.os.value |  | keyword |
| servicenow.event.os_address_width.display_value |  | keyword |
| servicenow.event.os_address_width.value |  | long |
| servicenow.event.os_domain.display_value |  | keyword |
| servicenow.event.os_domain.value |  | keyword |
| servicenow.event.os_service_pack.display_value |  | keyword |
| servicenow.event.os_service_pack.value |  | keyword |
| servicenow.event.os_version.display_value |  | keyword |
| servicenow.event.os_version.value |  | keyword |
| servicenow.event.outside_maintenance_schedule.display_value |  | boolean |
| servicenow.event.outside_maintenance_schedule.value |  | boolean |
| servicenow.event.owned_by.display_value |  | keyword |
| servicenow.event.owned_by.value |  | keyword |
| servicenow.event.parent.display_value |  | keyword |
| servicenow.event.parent.value |  | keyword |
| servicenow.event.parent_incident.display_value |  | keyword |
| servicenow.event.parent_incident.value |  | keyword |
| servicenow.event.password_needs_reset.display_value |  | boolean |
| servicenow.event.password_needs_reset.value |  | boolean |
| servicenow.event.percent_outage.display_value |  | keyword |
| servicenow.event.percent_outage.value |  | long |
| servicenow.event.phase.display_value |  | keyword |
| servicenow.event.phase.value |  | keyword |
| servicenow.event.phase_state.display_value |  | keyword |
| servicenow.event.phase_state.value |  | keyword |
| servicenow.event.phone.display_value |  | keyword |
| servicenow.event.phone.value |  | keyword |
| servicenow.event.phone_territory.display_value |  | keyword |
| servicenow.event.phone_territory.value |  | keyword |
| servicenow.event.photo.display_value |  | keyword |
| servicenow.event.photo.value |  | keyword |
| servicenow.event.pid.display_value |  | keyword |
| servicenow.event.pid.value |  | long |
| servicenow.event.planned_end_date.display_value |  | date |
| servicenow.event.planned_end_date.value |  | date |
| servicenow.event.planned_start_date.display_value |  | date |
| servicenow.event.planned_start_date.value |  | date |
| servicenow.event.platform.display_value |  | keyword |
| servicenow.event.platform.value |  | keyword |
| servicenow.event.platform_host.display_value |  | keyword |
| servicenow.event.platform_host.value |  | keyword |
| servicenow.event.po_number.display_value |  | keyword |
| servicenow.event.po_number.value |  | keyword |
| servicenow.event.pool_name.display_value |  | keyword |
| servicenow.event.pool_name.value |  | keyword |
| servicenow.event.port.display_value |  | keyword |
| servicenow.event.port.value |  | long |
| servicenow.event.portfolio_status.display_value |  | keyword |
| servicenow.event.portfolio_status.value |  | keyword |
| servicenow.event.power_state.display_value |  | keyword |
| servicenow.event.power_state.value |  | keyword |
| servicenow.event.pre_allocated.display_value |  | boolean |
| servicenow.event.pre_allocated.value |  | boolean |
| servicenow.event.preferred_language.display_value |  | keyword |
| servicenow.event.preferred_language.value |  | keyword |
| servicenow.event.prerequisites.display_value |  | keyword |
| servicenow.event.prerequisites.value |  | keyword |
| servicenow.event.price.currency_display_value |  | keyword |
| servicenow.event.price.display_value |  | keyword |
| servicenow.event.price.value |  | double |
| servicenow.event.price_model.display_value |  | keyword |
| servicenow.event.price_model.value |  | keyword |
| servicenow.event.price_unit.display_value |  | keyword |
| servicenow.event.price_unit.value |  | keyword |
| servicenow.event.primary_contact.display_value |  | keyword |
| servicenow.event.primary_contact.value |  | keyword |
| servicenow.event.primary_location.display_value |  | keyword |
| servicenow.event.primary_location.value |  | keyword |
| servicenow.event.priority.display_value |  | keyword |
| servicenow.event.priority.value |  | long |
| servicenow.event.problem_id.display_value |  | keyword |
| servicenow.event.problem_id.value |  | keyword |
| servicenow.event.problem_state.display_value |  | keyword |
| servicenow.event.problem_state.value |  | long |
| servicenow.event.processor.display_value |  | keyword |
| servicenow.event.processor.value |  | keyword |
| servicenow.event.product_instance_id.display_value |  | keyword |
| servicenow.event.product_instance_id.value |  | keyword |
| servicenow.event.product_support_status.display_value |  | keyword |
| servicenow.event.product_support_status.value |  | keyword |
| servicenow.event.production_system.display_value |  | boolean |
| servicenow.event.production_system.value |  | boolean |
| servicenow.event.provided_by.display_value |  | keyword |
| servicenow.event.provided_by.value |  | keyword |
| servicenow.event.published.display_value |  | date |
| servicenow.event.published.value |  | date |
| servicenow.event.published_ref.display_value |  | keyword |
| servicenow.event.published_ref.value |  | keyword |
| servicenow.event.purchase_date.display_value |  | date |
| servicenow.event.purchase_date.value |  | date |
| servicenow.event.quantity.display_value |  | keyword |
| servicenow.event.quantity.value |  | long |
| servicenow.event.ram.display_value |  | keyword |
| servicenow.event.ram.value |  | long |
| servicenow.event.rating.display_value |  | keyword |
| servicenow.event.rating.value |  | keyword |
| servicenow.event.reason.display_value |  | keyword |
| servicenow.event.reason.value |  | keyword |
| servicenow.event.reassignment_count.display_value |  | keyword |
| servicenow.event.reassignment_count.value |  | long |
| servicenow.event.recurring_frequency.display_value |  | keyword |
| servicenow.event.recurring_frequency.value |  | keyword |
| servicenow.event.recurring_price.currency_display_value |  | keyword |
| servicenow.event.recurring_price.display_value |  | keyword |
| servicenow.event.recurring_price.value |  | double |
| servicenow.event.related_incidents.display_value |  | keyword |
| servicenow.event.related_incidents.value |  | long |
| servicenow.event.reopen_count.display_value |  | keyword |
| servicenow.event.reopen_count.value |  | long |
| servicenow.event.reopened_at.display_value |  | date |
| servicenow.event.reopened_at.value |  | date |
| servicenow.event.reopened_by.display_value |  | keyword |
| servicenow.event.reopened_by.value |  | keyword |
| servicenow.event.reopened_time.display_value |  | date |
| servicenow.event.reopened_time.value |  | date |
| servicenow.event.replacement_article.display_value |  | keyword |
| servicenow.event.replacement_article.value |  | keyword |
| servicenow.event.request.display_value |  | keyword |
| servicenow.event.request.value |  | keyword |
| servicenow.event.request_line.display_value |  | keyword |
| servicenow.event.request_line.value |  | keyword |
| servicenow.event.requested_by.display_value |  | keyword |
| servicenow.event.requested_by.value |  | keyword |
| servicenow.event.requested_by_date.display_value |  | date |
| servicenow.event.requested_by_date.value |  | date |
| servicenow.event.requested_for.display_value |  | keyword |
| servicenow.event.requested_for.value |  | keyword |
| servicenow.event.resale_price.currency_display_value |  | keyword |
| servicenow.event.resale_price.display_value |  | keyword |
| servicenow.event.resale_price.value |  | double |
| servicenow.event.reserved_for.display_value |  | keyword |
| servicenow.event.reserved_for.value |  | keyword |
| servicenow.event.residual.currency_display_value |  | keyword |
| servicenow.event.residual.display_value |  | keyword |
| servicenow.event.residual.value |  | double |
| servicenow.event.residual_date.display_value |  | date |
| servicenow.event.residual_date.value |  | date |
| servicenow.event.resold_value.currency_display_value |  | keyword |
| servicenow.event.resold_value.display_value |  | keyword |
| servicenow.event.resold_value.value |  | double |
| servicenow.event.resolution_code.display_value |  | keyword |
| servicenow.event.resolution_code.value |  | keyword |
| servicenow.event.resolved_at.display_value |  | date |
| servicenow.event.resolved_at.value |  | date |
| servicenow.event.resolved_by.display_value |  | keyword |
| servicenow.event.resolved_by.value |  | keyword |
| servicenow.event.retired.display_value |  | keyword |
| servicenow.event.retired.value |  | keyword |
| servicenow.event.retirement_date.display_value |  | date |
| servicenow.event.retirement_date.value |  | date |
| servicenow.event.review_comments.display_value |  | keyword |
| servicenow.event.review_comments.value |  | keyword |
| servicenow.event.review_date.display_value |  | date |
| servicenow.event.review_date.value |  | date |
| servicenow.event.review_outcome.display_value |  | keyword |
| servicenow.event.review_outcome.value |  | keyword |
| servicenow.event.review_status.display_value |  | keyword |
| servicenow.event.review_status.value |  | long |
| servicenow.event.rfc.display_value |  | keyword |
| servicenow.event.rfc.value |  | keyword |
| servicenow.event.risk.display_value |  | keyword |
| servicenow.event.risk.value |  | long |
| servicenow.event.risk_impact_analysis.display_value |  | keyword |
| servicenow.event.risk_impact_analysis.value |  | keyword |
| servicenow.event.roles.display_value |  | keyword |
| servicenow.event.roles.display_values_list |  | keyword |
| servicenow.event.roles.value |  | keyword |
| servicenow.event.route_reason.display_value |  | keyword |
| servicenow.event.route_reason.value |  | long |
| servicenow.event.rp_command_hash.display_value |  | keyword |
| servicenow.event.rp_command_hash.value |  | keyword |
| servicenow.event.rp_key_parameters_hash.display_value |  | keyword |
| servicenow.event.rp_key_parameters_hash.value |  | keyword |
| servicenow.event.running_process.display_value |  | keyword |
| servicenow.event.running_process.value |  | keyword |
| servicenow.event.running_process_command.display_value |  | keyword |
| servicenow.event.running_process_command.value |  | keyword |
| servicenow.event.running_process_key_parameters.display_value |  | keyword |
| servicenow.event.running_process_key_parameters.value |  | keyword |
| servicenow.event.salvage_value.currency_display_value |  | keyword |
| servicenow.event.salvage_value.display_value |  | keyword |
| servicenow.event.salvage_value.value |  | double |
| servicenow.event.sc_catalog.display_value |  | keyword |
| servicenow.event.sc_catalog.value |  | keyword |
| servicenow.event.schedule.display_value |  | keyword |
| servicenow.event.schedule.value |  | keyword |
| servicenow.event.scope.display_value |  | keyword |
| servicenow.event.scope.value |  | long |
| servicenow.event.serial_number.display_value |  | keyword |
| servicenow.event.serial_number.value |  | keyword |
| servicenow.event.service_classification.display_value |  | keyword |
| servicenow.event.service_classification.value |  | keyword |
| servicenow.event.service_level_requirement.display_value |  | keyword |
| servicenow.event.service_level_requirement.value |  | keyword |
| servicenow.event.service_offering.display_value |  | keyword |
| servicenow.event.service_offering.value |  | keyword |
| servicenow.event.service_owner_delegate.display_value |  | keyword |
| servicenow.event.service_owner_delegate.value |  | keyword |
| servicenow.event.service_status.display_value |  | keyword |
| servicenow.event.service_status.value |  | keyword |
| servicenow.event.severity.display_value |  | keyword |
| servicenow.event.severity.value |  | long |
| servicenow.event.short_description.display_value |  | keyword |
| servicenow.event.short_description.value |  | keyword |
| servicenow.event.skip_sync.display_value |  | boolean |
| servicenow.event.skip_sync.value |  | boolean |
| servicenow.event.sla.display_value |  | keyword |
| servicenow.event.sla.value |  | keyword |
| servicenow.event.sla_due.display_value |  | keyword |
| servicenow.event.sla_due.value |  | keyword |
| servicenow.event.software_install.display_value |  | keyword |
| servicenow.event.software_install.value |  | keyword |
| servicenow.event.software_license.display_value |  | keyword |
| servicenow.event.software_license.value |  | keyword |
| servicenow.event.software_version.display_value |  | keyword |
| servicenow.event.software_version.value |  | keyword |
| servicenow.event.source.display_value |  | keyword |
| servicenow.event.source.value |  | keyword |
| servicenow.event.spm_service_portfolio.display_value |  | keyword |
| servicenow.event.spm_service_portfolio.value |  | keyword |
| servicenow.event.spm_taxonomy_node.display_value |  | keyword |
| servicenow.event.spm_taxonomy_node.value |  | keyword |
| servicenow.event.stage.display_value |  | keyword |
| servicenow.event.stage.value |  | keyword |
| servicenow.event.stakeholders.display_value |  | keyword |
| servicenow.event.stakeholders.value |  | keyword |
| servicenow.event.start_date.display_value |  | date |
| servicenow.event.start_date.value |  | date |
| servicenow.event.state.display_value |  | keyword |
| servicenow.event.state.value |  | keyword |
| servicenow.event.std_change_producer_version.display_value |  | keyword |
| servicenow.event.std_change_producer_version.value |  | keyword |
| servicenow.event.stock_room.display_value |  | boolean |
| servicenow.event.stock_room.value |  | boolean |
| servicenow.event.stockroom.display_value |  | keyword |
| servicenow.event.stockroom.value |  | keyword |
| servicenow.event.street.display_value |  | keyword |
| servicenow.event.street.value |  | keyword |
| servicenow.event.subcategory.display_value |  | keyword |
| servicenow.event.subcategory.value |  | keyword |
| servicenow.event.substatus.display_value |  | keyword |
| servicenow.event.substatus.value |  | keyword |
| servicenow.event.support_group.display_value |  | keyword |
| servicenow.event.support_group.value |  | keyword |
| servicenow.event.support_vendor.display_value |  | keyword |
| servicenow.event.support_vendor.value |  | keyword |
| servicenow.event.supported_by.display_value |  | keyword |
| servicenow.event.supported_by.value |  | keyword |
| servicenow.event.sys_class_name.display_value |  | keyword |
| servicenow.event.sys_class_name.value |  | keyword |
| servicenow.event.sys_class_path.display_value |  | keyword |
| servicenow.event.sys_class_path.value |  | keyword |
| servicenow.event.sys_created_by.display_value |  | keyword |
| servicenow.event.sys_created_by.value |  | keyword |
| servicenow.event.sys_created_on.display_value |  | date |
| servicenow.event.sys_created_on.value |  | date |
| servicenow.event.sys_domain.display_value |  | keyword |
| servicenow.event.sys_domain.value |  | keyword |
| servicenow.event.sys_domain_path.display_value |  | keyword |
| servicenow.event.sys_domain_path.value |  | keyword |
| servicenow.event.sys_id.display_value |  | keyword |
| servicenow.event.sys_id.value |  | keyword |
| servicenow.event.sys_mod_count.display_value |  | keyword |
| servicenow.event.sys_mod_count.value |  | long |
| servicenow.event.sys_tags.display_value |  | keyword |
| servicenow.event.sys_tags.value |  | keyword |
| servicenow.event.sys_updated_by.display_value |  | keyword |
| servicenow.event.sys_updated_by.value |  | keyword |
| servicenow.event.sys_updated_on.display_value |  | date |
| servicenow.event.sys_updated_on.value |  | date |
| servicenow.event.sys_view_count.display_value |  | keyword |
| servicenow.event.sys_view_count.value |  | long |
| servicenow.event.table_name |  | keyword |
| servicenow.event.task.display_value |  | keyword |
| servicenow.event.task.value |  | keyword |
| servicenow.event.task_effective_number.display_value |  | keyword |
| servicenow.event.task_effective_number.value |  | keyword |
| servicenow.event.taxonomy_topic.display_value |  | keyword |
| servicenow.event.taxonomy_topic.value |  | keyword |
| servicenow.event.tcp_port.display_value |  | keyword |
| servicenow.event.tcp_port.value |  | keyword |
| servicenow.event.technology_stack.display_value |  | keyword |
| servicenow.event.technology_stack.value |  | keyword |
| servicenow.event.test_plan.display_value |  | keyword |
| servicenow.event.test_plan.value |  | keyword |
| servicenow.event.text.display_value |  | keyword |
| servicenow.event.text.value |  | keyword |
| servicenow.event.time_format.display_value |  | keyword |
| servicenow.event.time_format.value |  | keyword |
| servicenow.event.time_worked.display_value |  | keyword |
| servicenow.event.time_worked.value |  | keyword |
| servicenow.event.time_zone.display_value |  | keyword |
| servicenow.event.time_zone.value |  | keyword |
| servicenow.event.title.display_value |  | keyword |
| servicenow.event.title.value |  | keyword |
| servicenow.event.topic.display_value |  | keyword |
| servicenow.event.topic.value |  | keyword |
| servicenow.event.total_memory.display_value |  | keyword |
| servicenow.event.total_memory.value |  | long |
| servicenow.event.total_vulnerable_items.display_value |  | keyword |
| servicenow.event.total_vulnerable_items.value |  | long |
| servicenow.event.type.display_value |  | keyword |
| servicenow.event.type.value |  | keyword |
| servicenow.event.unauthorized.display_value |  | boolean |
| servicenow.event.unauthorized.value |  | boolean |
| servicenow.event.unit_description.display_value |  | keyword |
| servicenow.event.unit_description.value |  | keyword |
| servicenow.event.universal_request.display_value |  | keyword |
| servicenow.event.universal_request.value |  | keyword |
| servicenow.event.unverified.display_value |  | boolean |
| servicenow.event.unverified.value |  | boolean |
| servicenow.event.upon_approval.display_value |  | keyword |
| servicenow.event.upon_approval.value |  | keyword |
| servicenow.event.upon_reject.display_value |  | keyword |
| servicenow.event.upon_reject.value |  | keyword |
| servicenow.event.urgency.display_value |  | keyword |
| servicenow.event.urgency.value |  | long |
| servicenow.event.url.display_value |  | keyword |
| servicenow.event.url.value |  | keyword |
| servicenow.event.use_count.display_value |  | keyword |
| servicenow.event.use_count.value |  | long |
| servicenow.event.used_for.display_value |  | keyword |
| servicenow.event.used_for.value |  | keyword |
| servicenow.event.user.display_value |  | keyword |
| servicenow.event.user.value |  | keyword |
| servicenow.event.user_base.display_value |  | keyword |
| servicenow.event.user_base.value |  | keyword |
| servicenow.event.user_group.display_value |  | keyword |
| servicenow.event.user_group.value |  | keyword |
| servicenow.event.user_input.display_value |  | keyword |
| servicenow.event.user_input.value |  | keyword |
| servicenow.event.user_name.display_value |  | keyword |
| servicenow.event.user_name.value |  | keyword |
| servicenow.event.user_password.display_value |  | keyword |
| servicenow.event.user_password.value |  | keyword |
| servicenow.event.valid_to.display_value |  | keyword |
| servicenow.event.valid_to.value |  | keyword |
| servicenow.event.vcenter_ref.display_value |  | keyword |
| servicenow.event.vcenter_ref.value |  | keyword |
| servicenow.event.vcenter_uuid.display_value |  | keyword |
| servicenow.event.vcenter_uuid.value |  | keyword |
| servicenow.event.vendor.display_value |  | keyword |
| servicenow.event.vendor.value |  | keyword |
| servicenow.event.version.display_value |  | keyword |
| servicenow.event.version.value |  | keyword |
| servicenow.event.view_as_allowed.display_value |  | boolean |
| servicenow.event.view_as_allowed.value |  | boolean |
| servicenow.event.vip.display_value |  | boolean |
| servicenow.event.vip.value |  | boolean |
| servicenow.event.virtual.display_value |  | boolean |
| servicenow.event.virtual.value |  | boolean |
| servicenow.event.vulnerability_risk_score.display_value |  | keyword |
| servicenow.event.vulnerability_risk_score.value |  | long |
| servicenow.event.warranty_expiration.display_value |  | date |
| servicenow.event.warranty_expiration.value |  | date |
| servicenow.event.watch_list.display_value |  | keyword |
| servicenow.event.watch_list.value |  | keyword |
| servicenow.event.web_service_access_only.display_value |  | boolean |
| servicenow.event.web_service_access_only.value |  | boolean |
| servicenow.event.wiki.display_value |  | keyword |
| servicenow.event.wiki.value |  | keyword |
| servicenow.event.windows_host.display_value |  | keyword |
| servicenow.event.windows_host.value |  | keyword |
| servicenow.event.work_end.display_value |  | date |
| servicenow.event.work_end.value |  | date |
| servicenow.event.work_notes.display_value |  | keyword |
| servicenow.event.work_notes.value |  | keyword |
| servicenow.event.work_notes_list.display_value |  | keyword |
| servicenow.event.work_notes_list.value |  | keyword |
| servicenow.event.work_start.display_value |  | date |
| servicenow.event.work_start.value |  | date |
| servicenow.event.workaround.display_value |  | keyword |
| servicenow.event.workaround.value |  | keyword |
| servicenow.event.workaround_applied.display_value |  | boolean |
| servicenow.event.workaround_applied.value |  | boolean |
| servicenow.event.workaround_communicated_at.display_value |  | date |
| servicenow.event.workaround_communicated_at.value |  | date |
| servicenow.event.workaround_communicated_by.display_value |  | keyword |
| servicenow.event.workaround_communicated_by.value |  | keyword |
| servicenow.event.workflow_state.display_value |  | keyword |
| servicenow.event.workflow_state.value |  | keyword |
| servicenow.event.xml.display_value |  | keyword |
| servicenow.event.xml.value |  | keyword |
| servicenow.event.zip.display_value |  | keyword |
| servicenow.event.zip.value |  | keyword |
| tags | User defined tags. | keyword |

