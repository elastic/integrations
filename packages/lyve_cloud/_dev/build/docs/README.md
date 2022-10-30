# Lyve Cloud Log Integration

The Lyve Cloud Log Integration offers users a way to collect logs from Lyve Cloud's [S3 bucket](https://www.seagate.com/gb/en/services/cloud/storage/)

When setting up the Lyve Cloud Integration you will need the target bucket name and the secret credentails to access the bucket. You can then visualize that data in Kibana and reference data when troubleshooting an issue.

# setup

Before adding the integration, you must complete the following tasks in the Lyve Cloud console to read the logs that are available in Lyve Cloud bucket:

1. Login with an administrator account.
2. Enable S3 API audit logs.
3. Create a target bucket to save logs.


# Configuration
1. Click on "add Lyve Cloud" button to create a policy for an elastic  agent.
2. Fill in the reqired information for ingesting the correct logs *access key*, *secret key*, *bucket name*, *endpoint* .
3. Give A "New agent policy name", click on "Save and continue" and click on "Add to hosts".
4. Follow Elastic's instructions to add an agent and you're set to go.
Collecting logs from S3 bucket.



Lyve Cloud provides a detailed records of supported S3 API calls. All these logs are written to a target bucket. Using the log information you can identify which events have occurred, when they have occurred and the user who performed the actions. 

