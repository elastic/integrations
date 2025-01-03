# Privileged Access Detection
The Privileged Access Detection package contains assets to detect anomalous privilege access activity in the Windows, Linux and Okta logs. This package requires a Platinum subscription. Please ensure that you have a Trial, Platinum, or Enterprise subscription before proceeding. This package is licensed under [Elastic License 2.0](https://www.elastic.co/licensing/elastic-license). 

For more detailed information refer to the following blog:
- [Detecting Lateral Movement activity: A new Kibana integration](https://www.elastic.co/blog/detecting-lateral-movement-activity-a-new-kibana-integration)

## Installation

1. **Add the Integration Package**: Install the package via **Management > Integrations > Add Privileged Access Detection**. Configure the integration name and agent policy. Click **Save and Continue**.
1. **Check the health of the transforms**: The transforms are scheduled to run every hour. These transforms create two indices: `ml_windows_privilege_type_pad.all` and `ml_okta_multiple_user_sessions_pad.all`. To check the health of the transforms go to **Management > Stack Management > Data > Transforms** under `logs-pad.pivot_transform_okta_multiple_sessions-default-<FLEET-TRANSFORM-VERSION>` and `logs-pad.pivot_transform_windows_privilege_list-default-<FLEET-TRANSFORM-VERSION>`.
1. **Create data views for anomaly detection jobs**: The anomaly detection jobs under this package rely on three indices. One index contains logs for Windows, Linux, and Okta (logs-*), while the second and third indices store Okta user session information and details about special Windows privileges assigned to a user, respectively, collected through a transform (`ml_okta_multiple_user_sessions_pad.all` and `ml_windows_privilege_type_pad.all`). Before enabling the anomaly detection jobs, create a data view with both index patterns.
    1. Go to **Stack Management > Kibana > Data Views** and click **Create data view**.
    1. Enter the name of your respective index patterns in the **Index pattern** box, i.e., `logs-*, ml_okta_multiple_user_sessions_pad.all, ml_windows_privilege_type_pad.all`, and copy the same in the **Name** field.
    1. Select `@timestamp` under the **Timestamp** field and click on **Save data view to Kibana**.
    1. Use the new data view (`logs-*, ml_okta_multiple_user_sessions_pad.all, ml_windows_privilege_type_pad.all`) to create anomaly detection jobs for this package.
1. **Add preconfigured anomaly detection jobs**: In **Machine Learning > Anomaly Detection**, when you create a job, you should see an option to `Use preconfigured jobs` with a card for **Privileged Access Detection**. When you select the card, you will see pre-configured anomaly detection jobs that you can enable depending on what makes the most sense for your environment. 
**_Note_**: In the Machine Learning app, these configurations are available only when data exists that matches the query specified in the [pad-ml file](https://github.com/elastic/integrations/blob/main/packages/pad/kibana/ml_module/pad-ml.json#L10). Additionally, we recommend backdating the datafeed for these anomaly detection jobs to a specific timeframe, as some datafeed queries are resource-intensive and may lead to query delays. We advise you to start the datafeed with 2-3 months' worth of data.
1. **Enabling detection rules**:  You can also enable detection rules to alert on Privileged Access activity in your environment, based on anomalies flagged by the above ML jobs. These rules are available as part of the Detection Engine, and can be found using the tag `Use Case: Privileged Access Detection`. See this [documentation](https://www.elastic.co/guide/en/security/current/prebuilt-rules-management.html#load-prebuilt-rules) for more information on importing and enabling the rules.

## Transform

To inspect the installed assets, you can navigate to **Stack Management > Data > Transforms**.

| Transform name      | Purpose                                                            | 	Source index  | Destination index                             | Alias              |
|---------------------|--------------------------------------------------------------------|----------------|-----------------------------------------------|--------------------|
| pad.pivot_transform_okta_multiple_sessions | 	Collects user session information for Okta events                 | 	logs-*        | 	ml_okta_multiple_user_sessions_pad-[version] | ml_okta_multiple_user_sessions_pad.all |
| pad.pivot_transform_windows_privilege_type | 	Collects special privileges assigned to a user for Windows events | 	logs-*        | 	ml_windows_privilege_type_pad-[version]      | ml_windows_privilege_type_pad.all |

When querying the destination indices for Okta and Windows logs, we advise using the alias for the destination index (`ml_okta_multiple_user_sessions_pad.all` and `ml_windows_privilege_type_pad.all`). In the event that the underlying package is upgraded, the alias will aid in maintaining the previous findings. 

### Anomaly Detection Jobs

| Job                                                  | Description                                                                        |
|------------------------------------------------------|------------------------------------------------------------------------------------|
| pad_windows_high_count_special_logon_events          | Detects unusually high special logon events initiated by a user.                   |
| pad_windows_high_count_special_privilege_use_events  | Detects unusually high special privilege use events initiated by a user.           |
| pad_windows_high_count_group_management_events          | Detects unusually high security group management events initiated by a user.       |
| pad_windows_high_count_user_account_management_events          | Detects unusually high security user account management events initiated by a user. |
| pad_windows_rare_privilege_assigned_to_user          | Detects an unusual privilege type assigned to a user.                              |
| pad_windows_rare_group_name_by_user         | Detects an unusual group name accessed by a user.                                  |
| pad_windows_rare_device_by_user          | Detects an unusual device accessed by a user.                                      |
| pad_windows_rare_source_ip_by_user          | Detects an unusual source IP address accessed by a user.                           |
| pad_windows_rare_region_name_by_user          | Detects an unusual region name for a user.                    |
| pad_linux_high_count_privileged_process_events_by_user         | Detects a spike in privileged commands executed by a user.                    |
| pad_linux_rare_process_executed_by_user          | Detects a rare process executed by a user.                    |
| pad_linux_high_sum_process_args_count_by_user          | Detects command lines executed by a user with an unusually high sum of process arguments.                   |
| pad_okta_spike_in_group_membership_changes          | Detects spike in group membership change events by a user.                    |
| pad_okta_spike_in_user_lifecycle_management_changes          | Detects spike in user lifecycle management change events by a user.                   |
| pad_okta_spike_in_group_privilege_changes          | Detects spike in group privilege change events by a user.                   |
| pad_okta_spike_in_group_application_assignment_changes          | Detects spike in group application assignment change events by a user.                   |
| pad_okta_spike_in_group_lifecycle_changes          | Detects spike in group lifecycle change events by a user.                   |
| pad_okta_high_sum_concurrent_sessions_by_user          | Detects an unusual sum of active sessions started by a user.                   |
| pad_okta_rare_source_ip_by_user          | Detects an unusual source IP address accessed by a user.                   |
| pad_okta_rare_region_name_by_user         | Detects an unusual region name for a user.                  |
| pad_okta_rare_host_name_by_user         | Detects an unusual host name for a user.                   |


## Licensing

Usage in production requires that you have a license key that permits use of machine learning features.