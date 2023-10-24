# Lyve Cloud
Lyve Cloud is your simple, trusted, and efficient on-demand solution for mass-capacity storage.Lyve Cloud is designed to be compatible with Amazon S3.

# Lyve Cloud Log Integration
The Lyve Cloud Log Integration offers users a way to collect logs from Lyve Cloud's [audit log bucket](https://www.seagate.com/gb/en/services/cloud/storage/)

When setting up the Lyve Cloud Integration you will need the target bucket name and the secret credentials to access the bucket. You can then visualize that data in Kibana and reference data when troubleshooting an issue.

Using the s3 API audit log information you can identify which events have occurred, when they have occurred and the user who performed the actions. 

# Setup
Before adding the integration, you must complete the following tasks in the Lyve Cloud console to read the logs that are available in Lyve Cloud bucket:

1. Login with an administrator account.
2. Create a target bucket to save logs.
3. Enable S3 API audit logs.
# Configuration
1. Click on "Add Lyve Cloud" button on the upper right side of the agent configuration screen to create a policy for an elastic agent.
2. Turn on the switch for Collecting logs from lyve cloud, under "Change defaults" fill in the reqired information for ingesting the correct logs *access key*, *secret key*, *bucket name* and *endpoint* .
3. Give A "New agent policy name", click on "Save and continue" and click on "Add to hosts".
4. Follow Elastic's instructions to add an agent and you're set to go.
# Dashboard and log monitoring
Filter out the Lyve Cloud logs using -
```data_stream.dataset:"lyve_cloud.audit" ```
when creating new dashboard or in other Analytics search fields inside the filter box.

{{fields "audit"}}

{{event "audit"}}
