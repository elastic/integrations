# ServiceNow Configuration Management Database

## Overview

The [ServiceNow CMDB](https://www.servicenow.com/products/servicenow-platform/configuration-management-database.html#benefits) integration helps organizations keep track of all their IT assets: computers, software and network devices, and shows how these items are related to each other. By having this information in one place, it is easier to manage changes, fix problems, and ensure everything is compliant with regulations. Essentially, it's a way to stay organized and know exactly what IT resources are available and how they work together.

The ServiceNow CMDB integration can be used in three different modes to collect logs:
- AWS S3 polling mode: ServiceNow CMDB writes data to S3, and Elastic Agent polls the S3 bucket by listing its contents and reading new files. Refer to the [ServiceNow documentation](https://www.servicenow.com/community/now-platform-forum/aws-s3-integration-with-servicenow/td-p/1121852) for how to integrate AWS S3 with ServiceNow for retrieving logs into an S3 bucket.
- AWS S3 SQS mode: ServiceNow CMDB writes data to S3; S3 sends a notification of a new object to SQS; the Elastic Agent receives the notification from SQS and then reads the S3 object. Multiple agents can be used in this mode.
- REST API mode: ServiceNow CMDB offers table APIs to retrieve data from its tables; the Elastic Agent polls these APIs to list their contents and read any new data. Visit this [link](https://developer.servicenow.com/dev.do#!/reference/api/washingtondc/rest/c_TableAPI#table-GET) for additional information about REST APIs.

## Compatibility

This module has been tested against the latest (updated Aug 1, 2024) ServiceNow CMDB API.

## Data streams

The ServiceNow integration supports both custom tables and the default tables offered by ServiceNow. Additionally, both types of tables are included in the data stream labeled `event`.

Below is a list of the default ones.

- **alm_hardware**
- **change_request**
- **change_task**
- **cmdb**
- **cmdb_ci**
- **cmdb_ci_app_server**
- **cmdb_ci_appl**
- **cmdb_ci_business_app**
- **cmdb_ci_computer**
- **cmdb_ci_db_instance**
- **cmdb_ci_esx_server**
- **cmdb_ci_hardware**
- **cmdb_ci_hyper_v_server**
- **cmdb_ci_infra_service**
- **cmdb_ci_linux_server**
- **cmdb_ci_server**
- **cmdb_ci_service**
- **cmdb_ci_vm**
- **cmdb_ci_win_server**
- **cmdb_rel_ci**
- **cmn_department**
- **cmn_location**
- **incident**
- **kb_knowledge**
- **problem**
- **sc_req_item**
- **sys_user**
- **sys_user_grmember**
- **sys_user_group**
- **task_ci**

**Note**:

1. This integration currently supports ECS mapping for default ServiceNow tables listed above. For custom tables created by users, ECS mapping is not automatically provided. If you want to add mappings for custom tables, please refer to this [tutorial guide](https://www.elastic.co/guide/en/fleet/current/data-streams-pipeline-tutorial.html).
2. For each table, a tag will be added based on the name of the table from which data is fetched.

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data through the REST API or AWS S3/SQS and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent. For more information, refer to the Elastic Agent [installation guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

## Setup

### To collect logs through REST API, follow the below steps:

- Your instance URL will serve as your base URL and will be formatted as follows: https://<instancename>.service-now.com
- Additionally, the username and password you use to log into your instance will be required to fetch logs in our integration.

### To collect logs through AWS S3, follow the below steps:

- With an AWS S3 bucket that has been set up, you can configure it with ServiceNow CMDB by integrating it using your AWS S3 credentials.

### To collect logs through AWS SQS, follow the below steps:

1. Assuming you've already set up a connection to push data into the AWS bucket you can follow the below steps; if not, see the section above.
2. To set up an SQS queue, follow "Step 1: Create an Amazon SQS Queue" as described in the [Amazon S3 user guide](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
   - While creating an access policy, use the bucket name configured to create a connection for AWS S3 in ServiceNow CMDB.
3. Configure event notifications for an S3 bucket according to the [Amazon S3 user guide](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
   - While creating `event notification` select the event type as s3:ObjectCreated:*, destination type SQS Queue, and select the queue name created in Step 2.

### Time Zone Selection:
- In the Data Collection section, use the `Timezone of ServiceNow Instance` dropdown to select your preferred timezone. The `.value` field for date data will always be in UTC, while the `.display_value` field can reflect your instance's selected timezone. The system default is set to America/Los_Angeles, but you can change this in your ServiceNow profile settings.
- Steps to See/Update the timezone in ServiceNow Instance:
  1. Click the user icon in the top-right corner of the ServiceNow interface.
  2. Select Profile from the dropdown menu.
  3. In your Profile settings, locate the Timezone option.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type ServiceNow CMDB.
3. Click on the "ServiceNow CMDB" integration from the search results.
4. Click on the "Add ServiceNow CMDB" button to add the integration.
5. While adding the integration, if you want to collect logs via REST API, then you have to put the following details:
   - API URL
   - username
   - password
   - table name
   - timezone
   - collect logs via REST API toggled on

   or if you want to collect logs via AWS S3, then you have to put the following details:
   - access key id
   - secret access key
   - bucket arn
   - timezone
   - collect logs via S3 Bucket toggled on

   or if you want to collect logs via AWS SQS, then you have to put the following details:
   - access key id
   - secret access key
   - queue url
   - timezone
   - collect logs via S3 Bucket toggled off
6. Click on "Save and Continue" to save the integration.

## Logs Reference

### Event

This is the `Event` dataset.

#### Example

An example event for `event` looks as following:

```json
{
    "@timestamp": "2024-09-24T05:39:40.000Z",
    "agent": {
        "ephemeral_id": "bfc335a1-e3f5-4fa2-9a3f-9fdbc16d82dc",
        "id": "303cd202-ea82-4538-b01f-8f78c98214c1",
        "name": "elastic-agent-39087",
        "type": "filebeat",
        "version": "8.14.0"
    },
    "data_stream": {
        "dataset": "servicenow_cmdb.event",
        "namespace": "50972",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "303cd202-ea82-4538-b01f-8f78c98214c1",
        "snapshot": false,
        "version": "8.14.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "configuration",
            "threat"
        ],
        "created": "2016-12-12T15:19:57.000Z",
        "dataset": "servicenow_cmdb.event",
        "id": "1c741bd70b2322007518478d83673af3",
        "ingested": "2024-10-30T05:16:58Z",
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
    "servicenow_cmdb": {
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
                "display_value": "2024-09-23T22:39:40.000-07:00"
            }
        }
    },
    "tags": [
        "incident",
        "hide_sensitive",
        "forwarded",
        "servicenow_cmdb-event"
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
| servicenow_cmdb.event.acquisition_method.display_value |  | keyword |
| servicenow_cmdb.event.acquisition_method.value |  | keyword |
| servicenow_cmdb.event.active.display_value |  | boolean |
| servicenow_cmdb.event.active.value |  | boolean |
| servicenow_cmdb.event.active_user_count.display_value |  | keyword |
| servicenow_cmdb.event.active_user_count.value |  | long |
| servicenow_cmdb.event.activity_due.display_value |  | date |
| servicenow_cmdb.event.activity_due.value |  | date |
| servicenow_cmdb.event.added_from_dynamic_ci.display_value |  | keyword |
| servicenow_cmdb.event.added_from_dynamic_ci.value |  | keyword |
| servicenow_cmdb.event.additional_assignee_list.display_value |  | keyword |
| servicenow_cmdb.event.additional_assignee_list.value |  | keyword |
| servicenow_cmdb.event.age.display_value |  | keyword |
| servicenow_cmdb.event.age.value |  | keyword |
| servicenow_cmdb.event.age_in_month.display_value |  | keyword |
| servicenow_cmdb.event.age_in_month.value |  | keyword |
| servicenow_cmdb.event.aliases.display_value |  | keyword |
| servicenow_cmdb.event.aliases.value |  | keyword |
| servicenow_cmdb.event.allotted_electric_power.display_value |  | keyword |
| servicenow_cmdb.event.allotted_electric_power.value |  | keyword |
| servicenow_cmdb.event.allotted_electric_power_unit.display_value |  | keyword |
| servicenow_cmdb.event.allotted_electric_power_unit.value |  | keyword |
| servicenow_cmdb.event.apm_business_process.display_value |  | keyword |
| servicenow_cmdb.event.apm_business_process.value |  | keyword |
| servicenow_cmdb.event.application_manager.display_value |  | keyword |
| servicenow_cmdb.event.application_manager.value |  | keyword |
| servicenow_cmdb.event.application_type.display_value |  | keyword |
| servicenow_cmdb.event.application_type.value |  | keyword |
| servicenow_cmdb.event.applied.display_value |  | boolean |
| servicenow_cmdb.event.applied.value |  | boolean |
| servicenow_cmdb.event.applied_date.display_value |  | date |
| servicenow_cmdb.event.applied_date.value |  | date |
| servicenow_cmdb.event.appraisal_fiscal_type.display_value |  | keyword |
| servicenow_cmdb.event.appraisal_fiscal_type.value |  | keyword |
| servicenow_cmdb.event.approval.display_value |  | keyword |
| servicenow_cmdb.event.approval.value |  | keyword |
| servicenow_cmdb.event.approval_history.display_value |  | keyword |
| servicenow_cmdb.event.approval_history.value |  | keyword |
| servicenow_cmdb.event.approval_set.display_value |  | date |
| servicenow_cmdb.event.approval_set.value |  | date |
| servicenow_cmdb.event.architecture_type.display_value |  | keyword |
| servicenow_cmdb.event.architecture_type.value |  | keyword |
| servicenow_cmdb.event.article_type.display_value |  | keyword |
| servicenow_cmdb.event.article_type.value |  | keyword |
| servicenow_cmdb.event.asset.display_value |  | keyword |
| servicenow_cmdb.event.asset.value |  | keyword |
| servicenow_cmdb.event.asset_function.display_value |  | keyword |
| servicenow_cmdb.event.asset_function.value |  | keyword |
| servicenow_cmdb.event.asset_tag.display_value |  | keyword |
| servicenow_cmdb.event.asset_tag.value |  | keyword |
| servicenow_cmdb.event.assigned.display_value |  | date |
| servicenow_cmdb.event.assigned.value |  | date |
| servicenow_cmdb.event.assigned_to.display_value |  | keyword |
| servicenow_cmdb.event.assigned_to.value |  | keyword |
| servicenow_cmdb.event.assignment_group.display_value |  | keyword |
| servicenow_cmdb.event.assignment_group.value |  | keyword |
| servicenow_cmdb.event.attestation_score.display_value |  | keyword |
| servicenow_cmdb.event.attestation_score.value |  | long |
| servicenow_cmdb.event.attestation_status.display_value |  | keyword |
| servicenow_cmdb.event.attestation_status.value |  | keyword |
| servicenow_cmdb.event.attested.display_value |  | boolean |
| servicenow_cmdb.event.attested.value |  | boolean |
| servicenow_cmdb.event.attested_by.display_value |  | keyword |
| servicenow_cmdb.event.attested_by.value |  | keyword |
| servicenow_cmdb.event.attested_date.display_value |  | date |
| servicenow_cmdb.event.attested_date.value |  | date |
| servicenow_cmdb.event.attributes.display_value |  | keyword |
| servicenow_cmdb.event.attributes.value |  | keyword |
| servicenow_cmdb.event.audience_type.display_value |  | keyword |
| servicenow_cmdb.event.audience_type.value |  | keyword |
| servicenow_cmdb.event.author.display_value |  | keyword |
| servicenow_cmdb.event.author.value |  | keyword |
| servicenow_cmdb.event.avatar.display_value |  | keyword |
| servicenow_cmdb.event.avatar.value |  | keyword |
| servicenow_cmdb.event.backordered.display_value |  | boolean |
| servicenow_cmdb.event.backordered.value |  | boolean |
| servicenow_cmdb.event.backout_plan.display_value |  | keyword |
| servicenow_cmdb.event.backout_plan.value |  | keyword |
| servicenow_cmdb.event.beneficiary.display_value |  | keyword |
| servicenow_cmdb.event.beneficiary.value |  | keyword |
| servicenow_cmdb.event.billable.display_value |  | boolean |
| servicenow_cmdb.event.billable.value |  | boolean |
| servicenow_cmdb.event.building.display_value |  | keyword |
| servicenow_cmdb.event.building.value |  | keyword |
| servicenow_cmdb.event.busines_criticality.display_value |  | keyword |
| servicenow_cmdb.event.busines_criticality.value |  | keyword |
| servicenow_cmdb.event.business_contact.display_value |  | keyword |
| servicenow_cmdb.event.business_contact.value |  | keyword |
| servicenow_cmdb.event.business_criticality.display_value |  | keyword |
| servicenow_cmdb.event.business_criticality.text_value |  | keyword |
| servicenow_cmdb.event.business_criticality.value |  | long |
| servicenow_cmdb.event.business_duration.display_value |  | keyword |
| servicenow_cmdb.event.business_duration.value |  | date |
| servicenow_cmdb.event.business_impact.display_value |  | keyword |
| servicenow_cmdb.event.business_impact.value |  | keyword |
| servicenow_cmdb.event.business_need.display_value |  | keyword |
| servicenow_cmdb.event.business_need.value |  | keyword |
| servicenow_cmdb.event.business_relation_manager.display_value |  | keyword |
| servicenow_cmdb.event.business_relation_manager.value |  | keyword |
| servicenow_cmdb.event.business_service.display_value |  | keyword |
| servicenow_cmdb.event.business_service.value |  | keyword |
| servicenow_cmdb.event.business_stc.display_value |  | keyword |
| servicenow_cmdb.event.business_stc.value |  | long |
| servicenow_cmdb.event.business_unit.display_value |  | keyword |
| servicenow_cmdb.event.business_unit.value |  | keyword |
| servicenow_cmdb.event.cab_date_time.display_value |  | date |
| servicenow_cmdb.event.cab_date_time.value |  | date |
| servicenow_cmdb.event.cab_delegate.display_value |  | keyword |
| servicenow_cmdb.event.cab_delegate.value |  | keyword |
| servicenow_cmdb.event.cab_recommendation.display_value |  | keyword |
| servicenow_cmdb.event.cab_recommendation.value |  | keyword |
| servicenow_cmdb.event.cab_required.display_value |  | boolean |
| servicenow_cmdb.event.cab_required.value |  | boolean |
| servicenow_cmdb.event.calendar_duration.display_value |  | keyword |
| servicenow_cmdb.event.calendar_duration.value |  | date |
| servicenow_cmdb.event.calendar_integration.display_value |  | keyword |
| servicenow_cmdb.event.calendar_integration.value |  | long |
| servicenow_cmdb.event.calendar_stc.display_value |  | keyword |
| servicenow_cmdb.event.calendar_stc.value |  | long |
| servicenow_cmdb.event.caller_id.display_value |  | keyword |
| servicenow_cmdb.event.caller_id.value |  | keyword |
| servicenow_cmdb.event.can_print.display_value |  | boolean |
| servicenow_cmdb.event.can_print.value |  | boolean |
| servicenow_cmdb.event.can_read_user_criteria.display_value |  | keyword |
| servicenow_cmdb.event.can_read_user_criteria.value |  | keyword |
| servicenow_cmdb.event.cannot_read_user_criteria.display_value |  | keyword |
| servicenow_cmdb.event.cannot_read_user_criteria.value |  | keyword |
| servicenow_cmdb.event.cat_item.display_value |  | keyword |
| servicenow_cmdb.event.cat_item.value |  | keyword |
| servicenow_cmdb.event.category.display_value |  | keyword |
| servicenow_cmdb.event.category.value |  | keyword |
| servicenow_cmdb.event.cause.display_value |  | keyword |
| servicenow_cmdb.event.cause.value |  | keyword |
| servicenow_cmdb.event.cause_notes.display_value |  | keyword |
| servicenow_cmdb.event.cause_notes.value |  | keyword |
| servicenow_cmdb.event.caused_by.display_value |  | keyword |
| servicenow_cmdb.event.caused_by.value |  | keyword |
| servicenow_cmdb.event.cd_rom.display_value |  | boolean |
| servicenow_cmdb.event.cd_rom.value |  | boolean |
| servicenow_cmdb.event.cd_speed.display_value |  | keyword |
| servicenow_cmdb.event.cd_speed.value |  | double |
| servicenow_cmdb.event.certified.display_value |  | boolean |
| servicenow_cmdb.event.certified.value |  | boolean |
| servicenow_cmdb.event.change_control.display_value |  | keyword |
| servicenow_cmdb.event.change_control.value |  | keyword |
| servicenow_cmdb.event.change_plan.display_value |  | keyword |
| servicenow_cmdb.event.change_plan.value |  | keyword |
| servicenow_cmdb.event.change_request.display_value |  | keyword |
| servicenow_cmdb.event.change_request.value |  | keyword |
| servicenow_cmdb.event.change_task_type.display_value |  | keyword |
| servicenow_cmdb.event.change_task_type.value |  | keyword |
| servicenow_cmdb.event.chassis_type.display_value |  | keyword |
| servicenow_cmdb.event.chassis_type.value |  | keyword |
| servicenow_cmdb.event.checked_in.display_value |  | date |
| servicenow_cmdb.event.checked_in.value |  | date |
| servicenow_cmdb.event.checked_out.display_value |  | date |
| servicenow_cmdb.event.checked_out.value |  | date |
| servicenow_cmdb.event.checkout.display_value |  | keyword |
| servicenow_cmdb.event.checkout.value |  | keyword |
| servicenow_cmdb.event.chg_model.display_value |  | keyword |
| servicenow_cmdb.event.chg_model.value |  | keyword |
| servicenow_cmdb.event.child.display_value |  | keyword |
| servicenow_cmdb.event.child.value |  | keyword |
| servicenow_cmdb.event.child_incidents.display_value |  | keyword |
| servicenow_cmdb.event.child_incidents.value |  | long |
| servicenow_cmdb.event.ci.display_value |  | keyword |
| servicenow_cmdb.event.ci.value |  | keyword |
| servicenow_cmdb.event.ci_item.display_value |  | keyword |
| servicenow_cmdb.event.ci_item.value |  | keyword |
| servicenow_cmdb.event.city.display_value |  | keyword |
| servicenow_cmdb.event.city.value |  | keyword |
| servicenow_cmdb.event.cl_port.display_value |  | keyword |
| servicenow_cmdb.event.cl_port.value |  | long |
| servicenow_cmdb.event.classification.display_value |  | keyword |
| servicenow_cmdb.event.classification.value |  | keyword |
| servicenow_cmdb.event.classifier.display_value |  | keyword |
| servicenow_cmdb.event.classifier.value |  | keyword |
| servicenow_cmdb.event.close_code.display_value |  | keyword |
| servicenow_cmdb.event.close_code.value |  | keyword |
| servicenow_cmdb.event.close_notes.display_value |  | keyword |
| servicenow_cmdb.event.close_notes.value |  | keyword |
| servicenow_cmdb.event.closed_at.display_value |  | date |
| servicenow_cmdb.event.closed_at.value |  | date |
| servicenow_cmdb.event.closed_by.display_value |  | keyword |
| servicenow_cmdb.event.closed_by.value |  | keyword |
| servicenow_cmdb.event.cluster_id.display_value |  | keyword |
| servicenow_cmdb.event.cluster_id.value |  | keyword |
| servicenow_cmdb.event.cluster_name.display_value |  | keyword |
| servicenow_cmdb.event.cluster_name.value |  | keyword |
| servicenow_cmdb.event.cmdb_ci.display_value |  | keyword |
| servicenow_cmdb.event.cmdb_ci.value |  | keyword |
| servicenow_cmdb.event.cmdb_ot_entity.display_value |  | keyword |
| servicenow_cmdb.event.cmdb_ot_entity.value |  | keyword |
| servicenow_cmdb.event.cmdb_software_product_model.display_value |  | keyword |
| servicenow_cmdb.event.cmdb_software_product_model.value |  | keyword |
| servicenow_cmdb.event.cmn_location_source.display_value |  | keyword |
| servicenow_cmdb.event.cmn_location_source.value |  | keyword |
| servicenow_cmdb.event.cmn_location_type.display_value |  | keyword |
| servicenow_cmdb.event.cmn_location_type.value |  | keyword |
| servicenow_cmdb.event.comments.display_value |  | keyword |
| servicenow_cmdb.event.comments.value |  | keyword |
| servicenow_cmdb.event.comments_and_work_notes.display_value |  | keyword |
| servicenow_cmdb.event.comments_and_work_notes.value |  | keyword |
| servicenow_cmdb.event.company.display_value |  | keyword |
| servicenow_cmdb.event.company.value |  | keyword |
| servicenow_cmdb.event.compatibility_dependencies.display_value |  | keyword |
| servicenow_cmdb.event.compatibility_dependencies.value |  | keyword |
| servicenow_cmdb.event.config_directory.display_value |  | keyword |
| servicenow_cmdb.event.config_directory.value |  | keyword |
| servicenow_cmdb.event.config_file.display_value |  | keyword |
| servicenow_cmdb.event.config_file.value |  | keyword |
| servicenow_cmdb.event.configuration_item.display_value |  | keyword |
| servicenow_cmdb.event.configuration_item.value |  | keyword |
| servicenow_cmdb.event.confirmed_at.display_value |  | date |
| servicenow_cmdb.event.confirmed_at.value |  | date |
| servicenow_cmdb.event.confirmed_by.display_value |  | keyword |
| servicenow_cmdb.event.confirmed_by.value |  | keyword |
| servicenow_cmdb.event.conflict_last_run.display_value |  | date |
| servicenow_cmdb.event.conflict_last_run.value |  | date |
| servicenow_cmdb.event.conflict_status.display_value |  | keyword |
| servicenow_cmdb.event.conflict_status.value |  | keyword |
| servicenow_cmdb.event.connection_state.display_value |  | keyword |
| servicenow_cmdb.event.connection_state.value |  | keyword |
| servicenow_cmdb.event.connection_strength.display_value |  | keyword |
| servicenow_cmdb.event.connection_strength.value |  | keyword |
| servicenow_cmdb.event.consumer_type.display_value |  | keyword |
| servicenow_cmdb.event.consumer_type.value |  | keyword |
| servicenow_cmdb.event.contact.display_value |  | keyword |
| servicenow_cmdb.event.contact.value |  | keyword |
| servicenow_cmdb.event.contact_type.display_value |  | keyword |
| servicenow_cmdb.event.contact_type.value |  | keyword |
| servicenow_cmdb.event.container.display_value |  | keyword |
| servicenow_cmdb.event.container.value |  | keyword |
| servicenow_cmdb.event.context.display_value |  | keyword |
| servicenow_cmdb.event.context.value |  | keyword |
| servicenow_cmdb.event.contract.display_value |  | keyword |
| servicenow_cmdb.event.contract.value |  | keyword |
| servicenow_cmdb.event.contract_end_date.display_value |  | date |
| servicenow_cmdb.event.contract_end_date.value |  | date |
| servicenow_cmdb.event.coordinates_retrieved_on.display_value |  | date |
| servicenow_cmdb.event.coordinates_retrieved_on.value |  | date |
| servicenow_cmdb.event.correlation_display.display_value |  | keyword |
| servicenow_cmdb.event.correlation_display.value |  | keyword |
| servicenow_cmdb.event.correlation_id.display_value |  | keyword |
| servicenow_cmdb.event.correlation_id.value |  | keyword |
| servicenow_cmdb.event.cost.currency_display_value |  | keyword |
| servicenow_cmdb.event.cost.display_value |  | keyword |
| servicenow_cmdb.event.cost.value |  | double |
| servicenow_cmdb.event.cost_cc.display_value |  | keyword |
| servicenow_cmdb.event.cost_cc.value |  | keyword |
| servicenow_cmdb.event.cost_center.display_value |  | keyword |
| servicenow_cmdb.event.cost_center.value |  | keyword |
| servicenow_cmdb.event.country.display_value |  | keyword |
| servicenow_cmdb.event.country.value |  | keyword |
| servicenow_cmdb.event.cpu_core_count.display_value |  | keyword |
| servicenow_cmdb.event.cpu_core_count.value |  | long |
| servicenow_cmdb.event.cpu_core_thread.display_value |  | keyword |
| servicenow_cmdb.event.cpu_core_thread.value |  | long |
| servicenow_cmdb.event.cpu_count.display_value |  | keyword |
| servicenow_cmdb.event.cpu_count.value |  | long |
| servicenow_cmdb.event.cpu_manufacturer.display_value |  | keyword |
| servicenow_cmdb.event.cpu_manufacturer.value |  | keyword |
| servicenow_cmdb.event.cpu_name.display_value |  | keyword |
| servicenow_cmdb.event.cpu_name.value |  | keyword |
| servicenow_cmdb.event.cpu_speed.display_value |  | keyword |
| servicenow_cmdb.event.cpu_speed.value |  | double |
| servicenow_cmdb.event.cpu_type.display_value |  | keyword |
| servicenow_cmdb.event.cpu_type.value |  | keyword |
| servicenow_cmdb.event.created_from.display_value |  | keyword |
| servicenow_cmdb.event.created_from.value |  | keyword |
| servicenow_cmdb.event.currency.display_value |  | keyword |
| servicenow_cmdb.event.currency.value |  | keyword |
| servicenow_cmdb.event.data_classification.display_value |  | keyword |
| servicenow_cmdb.event.data_classification.value |  | keyword |
| servicenow_cmdb.event.date_format.display_value |  | keyword |
| servicenow_cmdb.event.date_format.value |  | keyword |
| servicenow_cmdb.event.default_assignee.display_value |  | keyword |
| servicenow_cmdb.event.default_assignee.value |  | keyword |
| servicenow_cmdb.event.default_gateway.display_value |  | keyword |
| servicenow_cmdb.event.default_gateway.value |  | keyword |
| servicenow_cmdb.event.default_perspective.display_value |  | keyword |
| servicenow_cmdb.event.default_perspective.value |  | keyword |
| servicenow_cmdb.event.delivery_date.display_value |  | date |
| servicenow_cmdb.event.delivery_date.value |  | date |
| servicenow_cmdb.event.delivery_manager.display_value |  | keyword |
| servicenow_cmdb.event.delivery_manager.value |  | keyword |
| servicenow_cmdb.event.delivery_plan.display_value |  | keyword |
| servicenow_cmdb.event.delivery_plan.value |  | keyword |
| servicenow_cmdb.event.delivery_task.display_value |  | keyword |
| servicenow_cmdb.event.delivery_task.value |  | keyword |
| servicenow_cmdb.event.department.display_value |  | keyword |
| servicenow_cmdb.event.department.value |  | keyword |
| servicenow_cmdb.event.depreciated_amount.currency_display_value |  | keyword |
| servicenow_cmdb.event.depreciated_amount.display_value |  | keyword |
| servicenow_cmdb.event.depreciated_amount.value |  | double |
| servicenow_cmdb.event.depreciation.display_value |  | keyword |
| servicenow_cmdb.event.depreciation.value |  | keyword |
| servicenow_cmdb.event.depreciation_date.display_value |  | date |
| servicenow_cmdb.event.depreciation_date.value |  | date |
| servicenow_cmdb.event.dept_head.display_value |  | keyword |
| servicenow_cmdb.event.dept_head.value |  | keyword |
| servicenow_cmdb.event.description.display_value |  | keyword |
| servicenow_cmdb.event.description.value |  | keyword |
| servicenow_cmdb.event.direct.display_value |  | boolean |
| servicenow_cmdb.event.direct.value |  | boolean |
| servicenow_cmdb.event.disable_commenting.display_value |  | boolean |
| servicenow_cmdb.event.disable_commenting.value |  | boolean |
| servicenow_cmdb.event.disable_suggesting.display_value |  | boolean |
| servicenow_cmdb.event.disable_suggesting.value |  | boolean |
| servicenow_cmdb.event.discovery_source.display_value |  | keyword |
| servicenow_cmdb.event.discovery_source.value |  | keyword |
| servicenow_cmdb.event.disk_space.display_value |  | keyword |
| servicenow_cmdb.event.disk_space.value |  | double |
| servicenow_cmdb.event.display_attachments.display_value |  | boolean |
| servicenow_cmdb.event.display_attachments.value |  | boolean |
| servicenow_cmdb.event.display_name.display_value |  | keyword |
| servicenow_cmdb.event.display_name.value |  | keyword |
| servicenow_cmdb.event.disposal_reason.display_value |  | keyword |
| servicenow_cmdb.event.disposal_reason.value |  | keyword |
| servicenow_cmdb.event.dns_domain.display_value |  | keyword |
| servicenow_cmdb.event.dns_domain.value |  | keyword |
| servicenow_cmdb.event.dr_backup.display_value |  | keyword |
| servicenow_cmdb.event.dr_backup.value |  | keyword |
| servicenow_cmdb.event.due.display_value |  | date |
| servicenow_cmdb.event.due.value |  | date |
| servicenow_cmdb.event.due_date.display_value |  | date |
| servicenow_cmdb.event.due_date.value |  | date |
| servicenow_cmdb.event.due_in.display_value |  | keyword |
| servicenow_cmdb.event.due_in.value |  | keyword |
| servicenow_cmdb.event.duplicate.display_value |  | boolean |
| servicenow_cmdb.event.duplicate.value |  | boolean |
| servicenow_cmdb.event.duplicate_of.display_value |  | keyword |
| servicenow_cmdb.event.duplicate_of.value |  | keyword |
| servicenow_cmdb.event.edition.display_value |  | keyword |
| servicenow_cmdb.event.edition.value |  | keyword |
| servicenow_cmdb.event.eligible_for_refresh.display_value |  | boolean |
| servicenow_cmdb.event.eligible_for_refresh.value |  | boolean |
| servicenow_cmdb.event.email.display_value |  | keyword |
| servicenow_cmdb.event.email.value |  | keyword |
| servicenow_cmdb.event.emergency_tier.display_value |  | keyword |
| servicenow_cmdb.event.emergency_tier.value |  | keyword |
| servicenow_cmdb.event.employee_number.display_value |  | keyword |
| servicenow_cmdb.event.employee_number.value |  | keyword |
| servicenow_cmdb.event.enable_multifactor_authn.display_value |  | boolean |
| servicenow_cmdb.event.enable_multifactor_authn.value |  | boolean |
| servicenow_cmdb.event.end_date.display_value |  | date |
| servicenow_cmdb.event.end_date.value |  | date |
| servicenow_cmdb.event.environment.display_value |  | keyword |
| servicenow_cmdb.event.environment.value |  | keyword |
| servicenow_cmdb.event.escalation.display_value |  | keyword |
| servicenow_cmdb.event.escalation.value |  | long |
| servicenow_cmdb.event.estimated_delivery.display_value |  | date |
| servicenow_cmdb.event.estimated_delivery.value |  | date |
| servicenow_cmdb.event.exclude_manager.display_value |  | boolean |
| servicenow_cmdb.event.exclude_manager.value |  | boolean |
| servicenow_cmdb.event.expected_start.display_value |  | date |
| servicenow_cmdb.event.expected_start.value |  | date |
| servicenow_cmdb.event.expenditure_type.display_value |  | keyword |
| servicenow_cmdb.event.expenditure_type.value |  | keyword |
| servicenow_cmdb.event.failed_attempts.display_value |  | keyword |
| servicenow_cmdb.event.failed_attempts.value |  | long |
| servicenow_cmdb.event.fault_count.display_value |  | keyword |
| servicenow_cmdb.event.fault_count.value |  | long |
| servicenow_cmdb.event.fax_phone.display_value |  | keyword |
| servicenow_cmdb.event.fax_phone.value |  | keyword |
| servicenow_cmdb.event.federated_id.display_value |  | keyword |
| servicenow_cmdb.event.federated_id.value |  | keyword |
| servicenow_cmdb.event.firewall_status.display_value |  | keyword |
| servicenow_cmdb.event.firewall_status.value |  | keyword |
| servicenow_cmdb.event.first_discovered.display_value |  | date |
| servicenow_cmdb.event.first_discovered.value |  | date |
| servicenow_cmdb.event.first_name.display_value |  | keyword |
| servicenow_cmdb.event.first_name.value |  | keyword |
| servicenow_cmdb.event.first_reported_by_task.display_value |  | keyword |
| servicenow_cmdb.event.first_reported_by_task.value |  | keyword |
| servicenow_cmdb.event.fix_at.display_value |  | date |
| servicenow_cmdb.event.fix_at.value |  | date |
| servicenow_cmdb.event.fix_by.display_value |  | keyword |
| servicenow_cmdb.event.fix_by.value |  | keyword |
| servicenow_cmdb.event.fix_communicated_at.display_value |  | date |
| servicenow_cmdb.event.fix_communicated_at.value |  | date |
| servicenow_cmdb.event.fix_communicated_by.display_value |  | keyword |
| servicenow_cmdb.event.fix_communicated_by.value |  | keyword |
| servicenow_cmdb.event.fix_notes.display_value |  | keyword |
| servicenow_cmdb.event.fix_notes.value |  | keyword |
| servicenow_cmdb.event.flagged.display_value |  | boolean |
| servicenow_cmdb.event.flagged.value |  | boolean |
| servicenow_cmdb.event.floppy.display_value |  | keyword |
| servicenow_cmdb.event.floppy.value |  | keyword |
| servicenow_cmdb.event.flow_context.display_value |  | keyword |
| servicenow_cmdb.event.flow_context.value |  | keyword |
| servicenow_cmdb.event.follow_up.display_value |  | date |
| servicenow_cmdb.event.follow_up.value |  | date |
| servicenow_cmdb.event.form_factor.display_value |  | keyword |
| servicenow_cmdb.event.form_factor.value |  | keyword |
| servicenow_cmdb.event.fqdn.display_value |  | keyword |
| servicenow_cmdb.event.fqdn.value |  | keyword |
| servicenow_cmdb.event.full_name.display_value |  | keyword |
| servicenow_cmdb.event.full_name.value |  | keyword |
| servicenow_cmdb.event.gender.display_value |  | keyword |
| servicenow_cmdb.event.gender.value |  | keyword |
| servicenow_cmdb.event.generated_with_now_assist.display_value |  | boolean |
| servicenow_cmdb.event.generated_with_now_assist.value |  | boolean |
| servicenow_cmdb.event.gl_account.display_value |  | keyword |
| servicenow_cmdb.event.gl_account.value |  | keyword |
| servicenow_cmdb.event.group.display_value |  | keyword |
| servicenow_cmdb.event.group.value |  | keyword |
| servicenow_cmdb.event.group_list.display_value |  | keyword |
| servicenow_cmdb.event.group_list.value |  | keyword |
| servicenow_cmdb.event.hardware_status.display_value |  | keyword |
| servicenow_cmdb.event.hardware_status.value |  | keyword |
| servicenow_cmdb.event.hardware_substatus.display_value |  | keyword |
| servicenow_cmdb.event.hardware_substatus.value |  | keyword |
| servicenow_cmdb.event.head_count.display_value |  | keyword |
| servicenow_cmdb.event.head_count.value |  | long |
| servicenow_cmdb.event.helpful_count.display_value |  | keyword |
| servicenow_cmdb.event.helpful_count.value |  | keyword |
| servicenow_cmdb.event.hold_reason.display_value |  | keyword |
| servicenow_cmdb.event.hold_reason.value |  | keyword |
| servicenow_cmdb.event.home_phone.display_value |  | keyword |
| servicenow_cmdb.event.home_phone.value |  | keyword |
| servicenow_cmdb.event.host_name.display_value |  | keyword |
| servicenow_cmdb.event.host_name.value |  | keyword |
| servicenow_cmdb.event.hyper_threading.display_value |  | boolean |
| servicenow_cmdb.event.hyper_threading.value |  | boolean |
| servicenow_cmdb.event.id.display_value |  | keyword |
| servicenow_cmdb.event.id.value |  | keyword |
| servicenow_cmdb.event.image.display_value |  | keyword |
| servicenow_cmdb.event.image.value |  | keyword |
| servicenow_cmdb.event.impact.display_value |  | keyword |
| servicenow_cmdb.event.impact.value |  | long |
| servicenow_cmdb.event.implementation_plan.display_value |  | keyword |
| servicenow_cmdb.event.implementation_plan.value |  | keyword |
| servicenow_cmdb.event.incident_state.display_value |  | keyword |
| servicenow_cmdb.event.incident_state.value |  | long |
| servicenow_cmdb.event.include_members.display_value |  | boolean |
| servicenow_cmdb.event.include_members.value |  | boolean |
| servicenow_cmdb.event.install_date.display_value |  | date |
| servicenow_cmdb.event.install_date.value |  | date |
| servicenow_cmdb.event.install_directory.display_value |  | keyword |
| servicenow_cmdb.event.install_directory.value |  | keyword |
| servicenow_cmdb.event.install_status.display_value |  | keyword |
| servicenow_cmdb.event.install_status.value |  | long |
| servicenow_cmdb.event.install_type.display_value |  | keyword |
| servicenow_cmdb.event.install_type.value |  | keyword |
| servicenow_cmdb.event.instrumentation_metadata.display_value |  | keyword |
| servicenow_cmdb.event.instrumentation_metadata.value |  | keyword |
| servicenow_cmdb.event.internal_integration_user.display_value |  | boolean |
| servicenow_cmdb.event.internal_integration_user.value |  | boolean |
| servicenow_cmdb.event.internet_facing.display_value |  | boolean |
| servicenow_cmdb.event.internet_facing.value |  | boolean |
| servicenow_cmdb.event.introduction.display_value |  | keyword |
| servicenow_cmdb.event.introduction.value |  | keyword |
| servicenow_cmdb.event.invoice_number.display_value |  | keyword |
| servicenow_cmdb.event.invoice_number.value |  | keyword |
| servicenow_cmdb.event.ip_address.display_value |  | ip |
| servicenow_cmdb.event.ip_address.value |  | ip |
| servicenow_cmdb.event.is_clustered.display_value |  | boolean |
| servicenow_cmdb.event.is_clustered.value |  | boolean |
| servicenow_cmdb.event.it_application_owner.display_value |  | keyword |
| servicenow_cmdb.event.it_application_owner.value |  | keyword |
| servicenow_cmdb.event.justification.display_value |  | keyword |
| servicenow_cmdb.event.justification.value |  | keyword |
| servicenow_cmdb.event.kb_category.display_value |  | keyword |
| servicenow_cmdb.event.kb_category.value |  | keyword |
| servicenow_cmdb.event.kb_knowledge_base.display_value |  | keyword |
| servicenow_cmdb.event.kb_knowledge_base.value |  | keyword |
| servicenow_cmdb.event.kernel_release.display_value |  | keyword |
| servicenow_cmdb.event.kernel_release.value |  | keyword |
| servicenow_cmdb.event.knowledge.display_value |  | boolean |
| servicenow_cmdb.event.knowledge.value |  | boolean |
| servicenow_cmdb.event.known_error.display_value |  | boolean |
| servicenow_cmdb.event.known_error.value |  | boolean |
| servicenow_cmdb.event.last_change_date.display_value |  | keyword |
| servicenow_cmdb.event.last_change_date.value |  | keyword |
| servicenow_cmdb.event.last_discovered.display_value |  | date |
| servicenow_cmdb.event.last_discovered.value |  | date |
| servicenow_cmdb.event.last_login.display_value |  | date |
| servicenow_cmdb.event.last_login.value |  | date |
| servicenow_cmdb.event.last_login_time.display_value |  | date |
| servicenow_cmdb.event.last_login_time.value |  | date |
| servicenow_cmdb.event.last_name.display_value |  | keyword |
| servicenow_cmdb.event.last_name.value |  | keyword |
| servicenow_cmdb.event.last_review_date.display_value |  | date |
| servicenow_cmdb.event.last_review_date.value |  | date |
| servicenow_cmdb.event.lat_long_error.display_value |  | keyword |
| servicenow_cmdb.event.lat_long_error.value |  | keyword |
| servicenow_cmdb.event.latitude.display_value |  | double |
| servicenow_cmdb.event.latitude.value |  | double |
| servicenow_cmdb.event.ldap_server.display_value |  | keyword |
| servicenow_cmdb.event.ldap_server.value |  | keyword |
| servicenow_cmdb.event.lease_id.display_value |  | keyword |
| servicenow_cmdb.event.lease_id.value |  | keyword |
| servicenow_cmdb.event.life_cycle_stage.display_value |  | keyword |
| servicenow_cmdb.event.life_cycle_stage.value |  | keyword |
| servicenow_cmdb.event.life_cycle_stage_status.display_value |  | keyword |
| servicenow_cmdb.event.life_cycle_stage_status.value |  | keyword |
| servicenow_cmdb.event.listener_name.display_value |  | keyword |
| servicenow_cmdb.event.listener_name.value |  | keyword |
| servicenow_cmdb.event.location.display_value |  | keyword |
| servicenow_cmdb.event.location.value |  | keyword |
| servicenow_cmdb.event.locked_out.display_value |  | boolean |
| servicenow_cmdb.event.locked_out.value |  | boolean |
| servicenow_cmdb.event.logical_processor.display_value |  | keyword |
| servicenow_cmdb.event.logical_processor.value |  | keyword |
| servicenow_cmdb.event.longitude.display_value |  | double |
| servicenow_cmdb.event.longitude.value |  | double |
| servicenow_cmdb.event.mac_address.display_value |  | keyword |
| servicenow_cmdb.event.mac_address.value |  | keyword |
| servicenow_cmdb.event.made_sla.display_value |  | boolean |
| servicenow_cmdb.event.made_sla.value |  | boolean |
| servicenow_cmdb.event.maintenance_schedule.display_value |  | keyword |
| servicenow_cmdb.event.maintenance_schedule.value |  | keyword |
| servicenow_cmdb.event.major_problem.display_value |  | boolean |
| servicenow_cmdb.event.major_problem.value |  | boolean |
| servicenow_cmdb.event.managed_by.display_value |  | keyword |
| servicenow_cmdb.event.managed_by.value |  | keyword |
| servicenow_cmdb.event.managed_by_group.display_value |  | keyword |
| servicenow_cmdb.event.managed_by_group.value |  | keyword |
| servicenow_cmdb.event.manager.display_value |  | keyword |
| servicenow_cmdb.event.manager.value |  | keyword |
| servicenow_cmdb.event.manual_proposed_change.display_value |  | boolean |
| servicenow_cmdb.event.manual_proposed_change.value |  | boolean |
| servicenow_cmdb.event.manufacturer.display_value |  | keyword |
| servicenow_cmdb.event.manufacturer.value |  | keyword |
| servicenow_cmdb.event.meta.display_value |  | keyword |
| servicenow_cmdb.event.meta.value |  | keyword |
| servicenow_cmdb.event.meta_description.display_value |  | keyword |
| servicenow_cmdb.event.meta_description.value |  | keyword |
| servicenow_cmdb.event.metric_type.display_value |  | keyword |
| servicenow_cmdb.event.metric_type.value |  | keyword |
| servicenow_cmdb.event.middle_name.display_value |  | keyword |
| servicenow_cmdb.event.middle_name.value |  | keyword |
| servicenow_cmdb.event.mobile_phone.display_value |  | keyword |
| servicenow_cmdb.event.mobile_phone.value |  | keyword |
| servicenow_cmdb.event.model.display_value |  | keyword |
| servicenow_cmdb.event.model.value |  | keyword |
| servicenow_cmdb.event.model_category.display_value |  | keyword |
| servicenow_cmdb.event.model_category.value |  | keyword |
| servicenow_cmdb.event.model_component.display_value |  | keyword |
| servicenow_cmdb.event.model_component.value |  | keyword |
| servicenow_cmdb.event.model_component_id.display_value |  | keyword |
| servicenow_cmdb.event.model_component_id.value |  | keyword |
| servicenow_cmdb.event.model_id.display_value |  | keyword |
| servicenow_cmdb.event.model_id.value |  | keyword |
| servicenow_cmdb.event.model_number.display_value |  | keyword |
| servicenow_cmdb.event.model_number.value |  | keyword |
| servicenow_cmdb.event.monitor.display_value |  | boolean |
| servicenow_cmdb.event.monitor.value |  | boolean |
| servicenow_cmdb.event.monitoring_requirements.display_value |  | keyword |
| servicenow_cmdb.event.monitoring_requirements.value |  | keyword |
| servicenow_cmdb.event.morid.display_value |  | keyword |
| servicenow_cmdb.event.morid.value |  | keyword |
| servicenow_cmdb.event.most_frequent_user.display_value |  | keyword |
| servicenow_cmdb.event.most_frequent_user.value |  | keyword |
| servicenow_cmdb.event.name.display_value |  | keyword |
| servicenow_cmdb.event.name.value |  | keyword |
| servicenow_cmdb.event.next_assessment_date.display_value |  | date |
| servicenow_cmdb.event.next_assessment_date.value |  | date |
| servicenow_cmdb.event.notification.display_value |  | keyword |
| servicenow_cmdb.event.notification.value |  | long |
| servicenow_cmdb.event.notify.display_value |  | keyword |
| servicenow_cmdb.event.notify.value |  | long |
| servicenow_cmdb.event.number.display_value |  | keyword |
| servicenow_cmdb.event.number.value |  | keyword |
| servicenow_cmdb.event.object_id.display_value |  | keyword |
| servicenow_cmdb.event.object_id.value |  | keyword |
| servicenow_cmdb.event.old_status.display_value |  | keyword |
| servicenow_cmdb.event.old_status.value |  | keyword |
| servicenow_cmdb.event.old_substatus.display_value |  | keyword |
| servicenow_cmdb.event.old_substatus.value |  | keyword |
| servicenow_cmdb.event.on_hold.display_value |  | boolean |
| servicenow_cmdb.event.on_hold.value |  | boolean |
| servicenow_cmdb.event.on_hold_reason.display_value |  | keyword |
| servicenow_cmdb.event.on_hold_reason.value |  | keyword |
| servicenow_cmdb.event.on_hold_task.display_value |  | keyword |
| servicenow_cmdb.event.on_hold_task.value |  | keyword |
| servicenow_cmdb.event.opened_at.display_value |  | date |
| servicenow_cmdb.event.opened_at.value |  | date |
| servicenow_cmdb.event.opened_by.display_value |  | keyword |
| servicenow_cmdb.event.opened_by.value |  | keyword |
| servicenow_cmdb.event.operational_status.display_value |  | keyword |
| servicenow_cmdb.event.operational_status.value |  | long |
| servicenow_cmdb.event.order.display_value |  | keyword |
| servicenow_cmdb.event.order.value |  | long |
| servicenow_cmdb.event.order_date.display_value |  | date |
| servicenow_cmdb.event.order_date.value |  | date |
| servicenow_cmdb.event.order_guide.display_value |  | keyword |
| servicenow_cmdb.event.order_guide.value |  | keyword |
| servicenow_cmdb.event.organization_unit_count.display_value |  | keyword |
| servicenow_cmdb.event.organization_unit_count.value |  | long |
| servicenow_cmdb.event.origin_id.display_value |  | keyword |
| servicenow_cmdb.event.origin_id.value |  | keyword |
| servicenow_cmdb.event.origin_table.display_value |  | keyword |
| servicenow_cmdb.event.origin_table.value |  | keyword |
| servicenow_cmdb.event.os.display_value |  | keyword |
| servicenow_cmdb.event.os.value |  | keyword |
| servicenow_cmdb.event.os_address_width.display_value |  | keyword |
| servicenow_cmdb.event.os_address_width.value |  | long |
| servicenow_cmdb.event.os_domain.display_value |  | keyword |
| servicenow_cmdb.event.os_domain.value |  | keyword |
| servicenow_cmdb.event.os_service_pack.display_value |  | keyword |
| servicenow_cmdb.event.os_service_pack.value |  | keyword |
| servicenow_cmdb.event.os_version.display_value |  | keyword |
| servicenow_cmdb.event.os_version.value |  | keyword |
| servicenow_cmdb.event.outside_maintenance_schedule.display_value |  | boolean |
| servicenow_cmdb.event.outside_maintenance_schedule.value |  | boolean |
| servicenow_cmdb.event.owned_by.display_value |  | keyword |
| servicenow_cmdb.event.owned_by.value |  | keyword |
| servicenow_cmdb.event.parent.display_value |  | keyword |
| servicenow_cmdb.event.parent.value |  | keyword |
| servicenow_cmdb.event.parent_incident.display_value |  | keyword |
| servicenow_cmdb.event.parent_incident.value |  | keyword |
| servicenow_cmdb.event.password_needs_reset.display_value |  | boolean |
| servicenow_cmdb.event.password_needs_reset.value |  | boolean |
| servicenow_cmdb.event.percent_outage.display_value |  | keyword |
| servicenow_cmdb.event.percent_outage.value |  | long |
| servicenow_cmdb.event.phase.display_value |  | keyword |
| servicenow_cmdb.event.phase.value |  | keyword |
| servicenow_cmdb.event.phase_state.display_value |  | keyword |
| servicenow_cmdb.event.phase_state.value |  | keyword |
| servicenow_cmdb.event.phone.display_value |  | keyword |
| servicenow_cmdb.event.phone.value |  | keyword |
| servicenow_cmdb.event.phone_territory.display_value |  | keyword |
| servicenow_cmdb.event.phone_territory.value |  | keyword |
| servicenow_cmdb.event.photo.display_value |  | keyword |
| servicenow_cmdb.event.photo.value |  | keyword |
| servicenow_cmdb.event.pid.display_value |  | keyword |
| servicenow_cmdb.event.pid.value |  | long |
| servicenow_cmdb.event.planned_end_date.display_value |  | date |
| servicenow_cmdb.event.planned_end_date.value |  | date |
| servicenow_cmdb.event.planned_start_date.display_value |  | date |
| servicenow_cmdb.event.planned_start_date.value |  | date |
| servicenow_cmdb.event.platform.display_value |  | keyword |
| servicenow_cmdb.event.platform.value |  | keyword |
| servicenow_cmdb.event.platform_host.display_value |  | keyword |
| servicenow_cmdb.event.platform_host.value |  | keyword |
| servicenow_cmdb.event.po_number.display_value |  | keyword |
| servicenow_cmdb.event.po_number.value |  | keyword |
| servicenow_cmdb.event.pool_name.display_value |  | keyword |
| servicenow_cmdb.event.pool_name.value |  | keyword |
| servicenow_cmdb.event.port.display_value |  | keyword |
| servicenow_cmdb.event.port.value |  | long |
| servicenow_cmdb.event.portfolio_status.display_value |  | keyword |
| servicenow_cmdb.event.portfolio_status.value |  | keyword |
| servicenow_cmdb.event.power_state.display_value |  | keyword |
| servicenow_cmdb.event.power_state.value |  | keyword |
| servicenow_cmdb.event.pre_allocated.display_value |  | boolean |
| servicenow_cmdb.event.pre_allocated.value |  | boolean |
| servicenow_cmdb.event.preferred_language.display_value |  | keyword |
| servicenow_cmdb.event.preferred_language.value |  | keyword |
| servicenow_cmdb.event.prerequisites.display_value |  | keyword |
| servicenow_cmdb.event.prerequisites.value |  | keyword |
| servicenow_cmdb.event.price.currency_display_value |  | keyword |
| servicenow_cmdb.event.price.display_value |  | keyword |
| servicenow_cmdb.event.price.value |  | double |
| servicenow_cmdb.event.price_model.display_value |  | keyword |
| servicenow_cmdb.event.price_model.value |  | keyword |
| servicenow_cmdb.event.price_unit.display_value |  | keyword |
| servicenow_cmdb.event.price_unit.value |  | keyword |
| servicenow_cmdb.event.primary_contact.display_value |  | keyword |
| servicenow_cmdb.event.primary_contact.value |  | keyword |
| servicenow_cmdb.event.primary_location.display_value |  | keyword |
| servicenow_cmdb.event.primary_location.value |  | keyword |
| servicenow_cmdb.event.priority.display_value |  | keyword |
| servicenow_cmdb.event.priority.value |  | long |
| servicenow_cmdb.event.problem_id.display_value |  | keyword |
| servicenow_cmdb.event.problem_id.value |  | keyword |
| servicenow_cmdb.event.problem_state.display_value |  | keyword |
| servicenow_cmdb.event.problem_state.value |  | long |
| servicenow_cmdb.event.processor.display_value |  | keyword |
| servicenow_cmdb.event.processor.value |  | keyword |
| servicenow_cmdb.event.product_instance_id.display_value |  | keyword |
| servicenow_cmdb.event.product_instance_id.value |  | keyword |
| servicenow_cmdb.event.product_support_status.display_value |  | keyword |
| servicenow_cmdb.event.product_support_status.value |  | keyword |
| servicenow_cmdb.event.production_system.display_value |  | boolean |
| servicenow_cmdb.event.production_system.value |  | boolean |
| servicenow_cmdb.event.provided_by.display_value |  | keyword |
| servicenow_cmdb.event.provided_by.value |  | keyword |
| servicenow_cmdb.event.published.display_value |  | date |
| servicenow_cmdb.event.published.value |  | date |
| servicenow_cmdb.event.published_ref.display_value |  | keyword |
| servicenow_cmdb.event.published_ref.value |  | keyword |
| servicenow_cmdb.event.purchase_date.display_value |  | date |
| servicenow_cmdb.event.purchase_date.value |  | date |
| servicenow_cmdb.event.quantity.display_value |  | keyword |
| servicenow_cmdb.event.quantity.value |  | long |
| servicenow_cmdb.event.ram.display_value |  | keyword |
| servicenow_cmdb.event.ram.value |  | long |
| servicenow_cmdb.event.rating.display_value |  | keyword |
| servicenow_cmdb.event.rating.value |  | keyword |
| servicenow_cmdb.event.reason.display_value |  | keyword |
| servicenow_cmdb.event.reason.value |  | keyword |
| servicenow_cmdb.event.reassignment_count.display_value |  | keyword |
| servicenow_cmdb.event.reassignment_count.value |  | long |
| servicenow_cmdb.event.recurring_frequency.display_value |  | keyword |
| servicenow_cmdb.event.recurring_frequency.value |  | keyword |
| servicenow_cmdb.event.recurring_price.currency_display_value |  | keyword |
| servicenow_cmdb.event.recurring_price.display_value |  | keyword |
| servicenow_cmdb.event.recurring_price.value |  | double |
| servicenow_cmdb.event.related_incidents.display_value |  | keyword |
| servicenow_cmdb.event.related_incidents.value |  | long |
| servicenow_cmdb.event.reopen_count.display_value |  | keyword |
| servicenow_cmdb.event.reopen_count.value |  | long |
| servicenow_cmdb.event.reopened_at.display_value |  | date |
| servicenow_cmdb.event.reopened_at.value |  | date |
| servicenow_cmdb.event.reopened_by.display_value |  | keyword |
| servicenow_cmdb.event.reopened_by.value |  | keyword |
| servicenow_cmdb.event.reopened_time.display_value |  | date |
| servicenow_cmdb.event.reopened_time.value |  | date |
| servicenow_cmdb.event.replacement_article.display_value |  | keyword |
| servicenow_cmdb.event.replacement_article.value |  | keyword |
| servicenow_cmdb.event.request.display_value |  | keyword |
| servicenow_cmdb.event.request.value |  | keyword |
| servicenow_cmdb.event.request_line.display_value |  | keyword |
| servicenow_cmdb.event.request_line.value |  | keyword |
| servicenow_cmdb.event.requested_by.display_value |  | keyword |
| servicenow_cmdb.event.requested_by.value |  | keyword |
| servicenow_cmdb.event.requested_by_date.display_value |  | date |
| servicenow_cmdb.event.requested_by_date.value |  | date |
| servicenow_cmdb.event.requested_for.display_value |  | keyword |
| servicenow_cmdb.event.requested_for.value |  | keyword |
| servicenow_cmdb.event.resale_price.currency_display_value |  | keyword |
| servicenow_cmdb.event.resale_price.display_value |  | keyword |
| servicenow_cmdb.event.resale_price.value |  | double |
| servicenow_cmdb.event.reserved_for.display_value |  | keyword |
| servicenow_cmdb.event.reserved_for.value |  | keyword |
| servicenow_cmdb.event.residual.currency_display_value |  | keyword |
| servicenow_cmdb.event.residual.display_value |  | keyword |
| servicenow_cmdb.event.residual.value |  | double |
| servicenow_cmdb.event.residual_date.display_value |  | date |
| servicenow_cmdb.event.residual_date.value |  | date |
| servicenow_cmdb.event.resold_value.currency_display_value |  | keyword |
| servicenow_cmdb.event.resold_value.display_value |  | keyword |
| servicenow_cmdb.event.resold_value.value |  | double |
| servicenow_cmdb.event.resolution_code.display_value |  | keyword |
| servicenow_cmdb.event.resolution_code.value |  | keyword |
| servicenow_cmdb.event.resolved_at.display_value |  | date |
| servicenow_cmdb.event.resolved_at.value |  | date |
| servicenow_cmdb.event.resolved_by.display_value |  | keyword |
| servicenow_cmdb.event.resolved_by.value |  | keyword |
| servicenow_cmdb.event.retired.display_value |  | keyword |
| servicenow_cmdb.event.retired.value |  | keyword |
| servicenow_cmdb.event.retirement_date.display_value |  | date |
| servicenow_cmdb.event.retirement_date.value |  | date |
| servicenow_cmdb.event.review_comments.display_value |  | keyword |
| servicenow_cmdb.event.review_comments.value |  | keyword |
| servicenow_cmdb.event.review_date.display_value |  | date |
| servicenow_cmdb.event.review_date.value |  | date |
| servicenow_cmdb.event.review_outcome.display_value |  | keyword |
| servicenow_cmdb.event.review_outcome.value |  | keyword |
| servicenow_cmdb.event.review_status.display_value |  | keyword |
| servicenow_cmdb.event.review_status.value |  | long |
| servicenow_cmdb.event.rfc.display_value |  | keyword |
| servicenow_cmdb.event.rfc.value |  | keyword |
| servicenow_cmdb.event.risk.display_value |  | keyword |
| servicenow_cmdb.event.risk.value |  | long |
| servicenow_cmdb.event.risk_impact_analysis.display_value |  | keyword |
| servicenow_cmdb.event.risk_impact_analysis.value |  | keyword |
| servicenow_cmdb.event.roles.display_value |  | keyword |
| servicenow_cmdb.event.roles.display_values_list |  | keyword |
| servicenow_cmdb.event.roles.value |  | keyword |
| servicenow_cmdb.event.route_reason.display_value |  | keyword |
| servicenow_cmdb.event.route_reason.value |  | long |
| servicenow_cmdb.event.rp_command_hash.display_value |  | keyword |
| servicenow_cmdb.event.rp_command_hash.value |  | keyword |
| servicenow_cmdb.event.rp_key_parameters_hash.display_value |  | keyword |
| servicenow_cmdb.event.rp_key_parameters_hash.value |  | keyword |
| servicenow_cmdb.event.running_process.display_value |  | keyword |
| servicenow_cmdb.event.running_process.value |  | keyword |
| servicenow_cmdb.event.running_process_command.display_value |  | keyword |
| servicenow_cmdb.event.running_process_command.value |  | keyword |
| servicenow_cmdb.event.running_process_key_parameters.display_value |  | keyword |
| servicenow_cmdb.event.running_process_key_parameters.value |  | keyword |
| servicenow_cmdb.event.salvage_value.currency_display_value |  | keyword |
| servicenow_cmdb.event.salvage_value.display_value |  | keyword |
| servicenow_cmdb.event.salvage_value.value |  | double |
| servicenow_cmdb.event.sc_catalog.display_value |  | keyword |
| servicenow_cmdb.event.sc_catalog.value |  | keyword |
| servicenow_cmdb.event.schedule.display_value |  | keyword |
| servicenow_cmdb.event.schedule.value |  | keyword |
| servicenow_cmdb.event.scope.display_value |  | keyword |
| servicenow_cmdb.event.scope.value |  | long |
| servicenow_cmdb.event.serial_number.display_value |  | keyword |
| servicenow_cmdb.event.serial_number.value |  | keyword |
| servicenow_cmdb.event.service_classification.display_value |  | keyword |
| servicenow_cmdb.event.service_classification.value |  | keyword |
| servicenow_cmdb.event.service_level_requirement.display_value |  | keyword |
| servicenow_cmdb.event.service_level_requirement.value |  | keyword |
| servicenow_cmdb.event.service_offering.display_value |  | keyword |
| servicenow_cmdb.event.service_offering.value |  | keyword |
| servicenow_cmdb.event.service_owner_delegate.display_value |  | keyword |
| servicenow_cmdb.event.service_owner_delegate.value |  | keyword |
| servicenow_cmdb.event.service_status.display_value |  | keyword |
| servicenow_cmdb.event.service_status.value |  | keyword |
| servicenow_cmdb.event.severity.display_value |  | keyword |
| servicenow_cmdb.event.severity.value |  | long |
| servicenow_cmdb.event.short_description.display_value |  | keyword |
| servicenow_cmdb.event.short_description.value |  | keyword |
| servicenow_cmdb.event.skip_sync.display_value |  | boolean |
| servicenow_cmdb.event.skip_sync.value |  | boolean |
| servicenow_cmdb.event.sla.display_value |  | keyword |
| servicenow_cmdb.event.sla.value |  | keyword |
| servicenow_cmdb.event.sla_due.display_value |  | keyword |
| servicenow_cmdb.event.sla_due.value |  | keyword |
| servicenow_cmdb.event.software_install.display_value |  | keyword |
| servicenow_cmdb.event.software_install.value |  | keyword |
| servicenow_cmdb.event.software_license.display_value |  | keyword |
| servicenow_cmdb.event.software_license.value |  | keyword |
| servicenow_cmdb.event.software_version.display_value |  | keyword |
| servicenow_cmdb.event.software_version.value |  | keyword |
| servicenow_cmdb.event.source.display_value |  | keyword |
| servicenow_cmdb.event.source.value |  | keyword |
| servicenow_cmdb.event.spm_service_portfolio.display_value |  | keyword |
| servicenow_cmdb.event.spm_service_portfolio.value |  | keyword |
| servicenow_cmdb.event.spm_taxonomy_node.display_value |  | keyword |
| servicenow_cmdb.event.spm_taxonomy_node.value |  | keyword |
| servicenow_cmdb.event.stage.display_value |  | keyword |
| servicenow_cmdb.event.stage.value |  | keyword |
| servicenow_cmdb.event.stakeholders.display_value |  | keyword |
| servicenow_cmdb.event.stakeholders.value |  | keyword |
| servicenow_cmdb.event.start_date.display_value |  | date |
| servicenow_cmdb.event.start_date.value |  | date |
| servicenow_cmdb.event.state.display_value |  | keyword |
| servicenow_cmdb.event.state.value |  | keyword |
| servicenow_cmdb.event.std_change_producer_version.display_value |  | keyword |
| servicenow_cmdb.event.std_change_producer_version.value |  | keyword |
| servicenow_cmdb.event.stock_room.display_value |  | boolean |
| servicenow_cmdb.event.stock_room.value |  | boolean |
| servicenow_cmdb.event.stockroom.display_value |  | keyword |
| servicenow_cmdb.event.stockroom.value |  | keyword |
| servicenow_cmdb.event.street.display_value |  | keyword |
| servicenow_cmdb.event.street.value |  | keyword |
| servicenow_cmdb.event.subcategory.display_value |  | keyword |
| servicenow_cmdb.event.subcategory.value |  | keyword |
| servicenow_cmdb.event.substatus.display_value |  | keyword |
| servicenow_cmdb.event.substatus.value |  | keyword |
| servicenow_cmdb.event.support_group.display_value |  | keyword |
| servicenow_cmdb.event.support_group.value |  | keyword |
| servicenow_cmdb.event.support_vendor.display_value |  | keyword |
| servicenow_cmdb.event.support_vendor.value |  | keyword |
| servicenow_cmdb.event.supported_by.display_value |  | keyword |
| servicenow_cmdb.event.supported_by.value |  | keyword |
| servicenow_cmdb.event.sys_class_name.display_value |  | keyword |
| servicenow_cmdb.event.sys_class_name.value |  | keyword |
| servicenow_cmdb.event.sys_class_path.display_value |  | keyword |
| servicenow_cmdb.event.sys_class_path.value |  | keyword |
| servicenow_cmdb.event.sys_created_by.display_value |  | keyword |
| servicenow_cmdb.event.sys_created_by.value |  | keyword |
| servicenow_cmdb.event.sys_created_on.display_value |  | date |
| servicenow_cmdb.event.sys_created_on.value |  | date |
| servicenow_cmdb.event.sys_domain.display_value |  | keyword |
| servicenow_cmdb.event.sys_domain.value |  | keyword |
| servicenow_cmdb.event.sys_domain_path.display_value |  | keyword |
| servicenow_cmdb.event.sys_domain_path.value |  | keyword |
| servicenow_cmdb.event.sys_id.display_value |  | keyword |
| servicenow_cmdb.event.sys_id.value |  | keyword |
| servicenow_cmdb.event.sys_mod_count.display_value |  | keyword |
| servicenow_cmdb.event.sys_mod_count.value |  | long |
| servicenow_cmdb.event.sys_tags.display_value |  | keyword |
| servicenow_cmdb.event.sys_tags.value |  | keyword |
| servicenow_cmdb.event.sys_updated_by.display_value |  | keyword |
| servicenow_cmdb.event.sys_updated_by.value |  | keyword |
| servicenow_cmdb.event.sys_updated_on.display_value |  | date |
| servicenow_cmdb.event.sys_updated_on.value |  | date |
| servicenow_cmdb.event.sys_view_count.display_value |  | keyword |
| servicenow_cmdb.event.sys_view_count.value |  | long |
| servicenow_cmdb.event.task.display_value |  | keyword |
| servicenow_cmdb.event.task.value |  | keyword |
| servicenow_cmdb.event.task_effective_number.display_value |  | keyword |
| servicenow_cmdb.event.task_effective_number.value |  | keyword |
| servicenow_cmdb.event.taxonomy_topic.display_value |  | keyword |
| servicenow_cmdb.event.taxonomy_topic.value |  | keyword |
| servicenow_cmdb.event.tcp_port.display_value |  | keyword |
| servicenow_cmdb.event.tcp_port.value |  | keyword |
| servicenow_cmdb.event.technology_stack.display_value |  | keyword |
| servicenow_cmdb.event.technology_stack.value |  | keyword |
| servicenow_cmdb.event.test_plan.display_value |  | keyword |
| servicenow_cmdb.event.test_plan.value |  | keyword |
| servicenow_cmdb.event.text.display_value |  | keyword |
| servicenow_cmdb.event.text.value |  | keyword |
| servicenow_cmdb.event.time_format.display_value |  | keyword |
| servicenow_cmdb.event.time_format.value |  | keyword |
| servicenow_cmdb.event.time_worked.display_value |  | keyword |
| servicenow_cmdb.event.time_worked.value |  | keyword |
| servicenow_cmdb.event.time_zone.display_value |  | keyword |
| servicenow_cmdb.event.time_zone.value |  | keyword |
| servicenow_cmdb.event.title.display_value |  | keyword |
| servicenow_cmdb.event.title.value |  | keyword |
| servicenow_cmdb.event.topic.display_value |  | keyword |
| servicenow_cmdb.event.topic.value |  | keyword |
| servicenow_cmdb.event.total_memory.display_value |  | keyword |
| servicenow_cmdb.event.total_memory.value |  | long |
| servicenow_cmdb.event.total_vulnerable_items.display_value |  | keyword |
| servicenow_cmdb.event.total_vulnerable_items.value |  | long |
| servicenow_cmdb.event.type.display_value |  | keyword |
| servicenow_cmdb.event.type.value |  | keyword |
| servicenow_cmdb.event.unauthorized.display_value |  | boolean |
| servicenow_cmdb.event.unauthorized.value |  | boolean |
| servicenow_cmdb.event.unit_description.display_value |  | keyword |
| servicenow_cmdb.event.unit_description.value |  | keyword |
| servicenow_cmdb.event.universal_request.display_value |  | keyword |
| servicenow_cmdb.event.universal_request.value |  | keyword |
| servicenow_cmdb.event.unverified.display_value |  | boolean |
| servicenow_cmdb.event.unverified.value |  | boolean |
| servicenow_cmdb.event.upon_approval.display_value |  | keyword |
| servicenow_cmdb.event.upon_approval.value |  | keyword |
| servicenow_cmdb.event.upon_reject.display_value |  | keyword |
| servicenow_cmdb.event.upon_reject.value |  | keyword |
| servicenow_cmdb.event.urgency.display_value |  | keyword |
| servicenow_cmdb.event.urgency.value |  | long |
| servicenow_cmdb.event.url.display_value |  | keyword |
| servicenow_cmdb.event.url.value |  | keyword |
| servicenow_cmdb.event.use_count.display_value |  | keyword |
| servicenow_cmdb.event.use_count.value |  | long |
| servicenow_cmdb.event.used_for.display_value |  | keyword |
| servicenow_cmdb.event.used_for.value |  | keyword |
| servicenow_cmdb.event.user.display_value |  | keyword |
| servicenow_cmdb.event.user.value |  | keyword |
| servicenow_cmdb.event.user_base.display_value |  | keyword |
| servicenow_cmdb.event.user_base.value |  | keyword |
| servicenow_cmdb.event.user_group.display_value |  | keyword |
| servicenow_cmdb.event.user_group.value |  | keyword |
| servicenow_cmdb.event.user_input.display_value |  | keyword |
| servicenow_cmdb.event.user_input.value |  | keyword |
| servicenow_cmdb.event.user_name.display_value |  | keyword |
| servicenow_cmdb.event.user_name.value |  | keyword |
| servicenow_cmdb.event.user_password.display_value |  | keyword |
| servicenow_cmdb.event.user_password.value |  | keyword |
| servicenow_cmdb.event.valid_to.display_value |  | keyword |
| servicenow_cmdb.event.valid_to.value |  | keyword |
| servicenow_cmdb.event.vcenter_ref.display_value |  | keyword |
| servicenow_cmdb.event.vcenter_ref.value |  | keyword |
| servicenow_cmdb.event.vcenter_uuid.display_value |  | keyword |
| servicenow_cmdb.event.vcenter_uuid.value |  | keyword |
| servicenow_cmdb.event.vendor.display_value |  | keyword |
| servicenow_cmdb.event.vendor.value |  | keyword |
| servicenow_cmdb.event.version.display_value |  | keyword |
| servicenow_cmdb.event.version.value |  | keyword |
| servicenow_cmdb.event.view_as_allowed.display_value |  | boolean |
| servicenow_cmdb.event.view_as_allowed.value |  | boolean |
| servicenow_cmdb.event.vip.display_value |  | boolean |
| servicenow_cmdb.event.vip.value |  | boolean |
| servicenow_cmdb.event.virtual.display_value |  | boolean |
| servicenow_cmdb.event.virtual.value |  | boolean |
| servicenow_cmdb.event.vulnerability_risk_score.display_value |  | keyword |
| servicenow_cmdb.event.vulnerability_risk_score.value |  | long |
| servicenow_cmdb.event.warranty_expiration.display_value |  | date |
| servicenow_cmdb.event.warranty_expiration.value |  | date |
| servicenow_cmdb.event.watch_list.display_value |  | keyword |
| servicenow_cmdb.event.watch_list.value |  | keyword |
| servicenow_cmdb.event.web_service_access_only.display_value |  | boolean |
| servicenow_cmdb.event.web_service_access_only.value |  | boolean |
| servicenow_cmdb.event.wiki.display_value |  | keyword |
| servicenow_cmdb.event.wiki.value |  | keyword |
| servicenow_cmdb.event.windows_host.display_value |  | keyword |
| servicenow_cmdb.event.windows_host.value |  | keyword |
| servicenow_cmdb.event.work_end.display_value |  | date |
| servicenow_cmdb.event.work_end.value |  | date |
| servicenow_cmdb.event.work_notes.display_value |  | keyword |
| servicenow_cmdb.event.work_notes.value |  | keyword |
| servicenow_cmdb.event.work_notes_list.display_value |  | keyword |
| servicenow_cmdb.event.work_notes_list.value |  | keyword |
| servicenow_cmdb.event.work_start.display_value |  | date |
| servicenow_cmdb.event.work_start.value |  | date |
| servicenow_cmdb.event.workaround.display_value |  | keyword |
| servicenow_cmdb.event.workaround.value |  | keyword |
| servicenow_cmdb.event.workaround_applied.display_value |  | boolean |
| servicenow_cmdb.event.workaround_applied.value |  | boolean |
| servicenow_cmdb.event.workaround_communicated_at.display_value |  | date |
| servicenow_cmdb.event.workaround_communicated_at.value |  | date |
| servicenow_cmdb.event.workaround_communicated_by.display_value |  | keyword |
| servicenow_cmdb.event.workaround_communicated_by.value |  | keyword |
| servicenow_cmdb.event.workflow_state.display_value |  | keyword |
| servicenow_cmdb.event.workflow_state.value |  | keyword |
| servicenow_cmdb.event.xml.display_value |  | keyword |
| servicenow_cmdb.event.xml.value |  | keyword |
| servicenow_cmdb.event.zip.display_value |  | keyword |
| servicenow_cmdb.event.zip.value |  | keyword |
| tags | User defined tags. | keyword |

