# Google Cloud Integration

## Overview

The Google Cloud integration collects and parses Google Cloud [Audit Logs](https://cloud.google.com/logging/docs/audit), [VPC Flow Logs](https://cloud.google.com/vpc/docs/using-flow-logs), [Firewall Rules Logs](https://cloud.google.com/vpc/docs/firewall-rules-logging) and [Cloud DNS Logs](https://cloud.google.com/dns/docs/monitoring) that have been exported from Cloud Logging to a Google Pub/Sub topic sink.

## Authentication

To use this Google Cloud Platform (GCP) integration, you need to set up a *Service Account* with a few *Roles* and a *Service Account Key* to access data on your GCP project.

### Service Account

First, you need to [create a Service Account](https://cloud.google.com/iam/docs/creating-managing-service-accounts). A Service Account (SA) is a particular type of Google account intended to represent a non-human user who needs to access the GCP resources.

The Elastic Agent uses the SA to access data on Google Cloud Platform using the Google APIs.

### Roles

You need to grant your Service Account (SA) access to Google Cloud Platform resources adding one or more roles.

For this integration to work, you need to add the following roles to your SA:

- `Compute Viewer`
- `Monitoring Viewer`
- `Pub/Sub Viewer`
- `Pub/Sub Subscriber`

Always follow the "principle of least privilege" when adding a new role to your SA. If you haven't already, this might be a good moment to check out the [best practices for securing service accounts](https://cloud.google.com/iam/docs/best-practices-for-securing-service-accounts) guide.

### Service Account Keys

Now, with your brand new Service Account (SA) with access to Google Cloud Platform (GCP) resources, you need some credentials to associate with it: a Service Account Key.

From the list of SA:

1. Click the one you just created to open the detailed view.
2. From the Keys section, click "Add key" > "Create new key" and select JSON as the type.
3. Download and store the generated private key securely (remember, the private key can't be recovered from GCP if lost).

Optional: take some time to review the GCP's [best practices for managing service account keys](https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys).

## Configure the Integration Settings

The next step is to configure the general integration settings used for all logs from the supported services (Audit, DNS, Firewall, and VPC Flow).

The "Project Id" and either the "Credentials File" or "Credentials JSON" will need to be provided in the integration UI when adding the Google Cloud Platform integration.

### Project Id

The Project Id is the Google Cloud project ID where your resources exist.

### Credentials File vs Json

Based on your preference, specify the information in either the Credentials File OR the Credentials JSON field.

#### Option 1: Credentials File

Save the JSON file with the private key in a secure location of the file system, and make sure that the Elastic Agent has at least read-only privileges to this file.

Specify the file path in the Elastic Agent integration UI in the "Credentials File" field. For example: `/home/ubuntu/credentials.json`.

#### Option 2: Credentials JSON

Specify the content of the JSON file you downloaded from Google Cloud Platform directly in the Credentials JSON field in the Elastic Agent integration.

#### Recommendations

Elastic recommends using Credentials File, as in this method the credential information doesn’t leave your Google Cloud Platform environment. When using Credentials JSON, the integration stores the info in Elasticsearch, and the access is controlled based on policy permissions or access to underlying Elasticsearch data.

## Logs Collection Configuration

With a properly configured Service Account and the integration setting in place, it's time to start collecting some logs.

### Requirements

You need to create a few dedicated Google Cloud resources before starting, in detail:

- Log Sink
- Pub/Sub Topic
- Subscription

Elastic recommends separate Pub/Sub topics for each of the log types so that they can be parsed and stored in a specific data stream.

Here's an example of collecting Audit Logs using a Pub/Sub topic, a subscription, and a Log Router. We will create the resources in the Google Cloud Console and then configure the Google Cloud Platform integration.

### On the Google Cloud Console

At a high level, the steps required are:

- Visit "Logging" > "Log Router" > "Create Sink" and provide a sink name and description.
- In "Sink destination", select "Cloud Pub/Sub topic" as the sink service. Select an existing topic or "Create a topic". Note the topic name, as it will be provided in the Topic field in the Elastic agent configuration.
- If you created a new topic, you must remember to go to that topic and create a subscription for it. A subscription directs messages on a topic to subscribers. Note the "Subscription ID", as it will need to be entered in the "Subscription name" field in the ingtegration settings.
- Under "Choose logs to include in sink", for example add `logName:"cloudaudit.googleapis.com"` in the "Inclusion filter" to include all audit logs.

This is just an example; you will need to create your filter expression to select the log types you want to export to the Pub/Sub topic.

More example filters for different log types:

```text
#
# VPC Flow: logs for specific subnet
#
resource.type="gce_subnetwork" AND
log_id("compute.googleapis.com/vpc_flows") AND
resource.labels.subnetwork_name"=[SUBNET_NAME]"

#
# Audit: Google Compute Engine firewall rule deletion
#
resource.type="gce_firewall_rule" AND
log_id("cloudaudit.googleapis.com/activity") AND
protoPayload.methodName:"firewalls.delete" 

#
# DNS: all DNS queries
#
resource.type="dns_query"

#
# Firewall: logs for a given country
#
resource.type="gce_subnetwork" AND
log_id("compute.googleapis.com/firewall") AND
jsonPayload.remote_location.country=[COUNTRY_ISO_ALPHA_3]
```

Start working on your query using the Google Cloud [Logs Explorer](https://console.cloud.google.com/logs/query), so you can preview and pintpoint the exact log types you want to forward to your Elastic Stack.

To learn more, please read how to [Build queries in the Logs Explorer](https://cloud.google.com/logging/docs/view/building-queries), and take a look at the [Sample queries using the Logs Explorer](https://cloud.google.com/logging/docs/view/query-library-preview) page in the Google Cloud docs.

### On Kibana

Visit "Management" > "Integrations" > "Installed Integrations" > "Google Cloud Platform" and select the "Integration Policies" tab. Select the integration policy you previously created.

From the list of services, select "Google Cloud Platform (GCP) audit logs (gcp-pubsub)" and:

- On the "Topic" field, specify the "topic name" you noted before on the Google Cloud Console.
- On the "Subscription Name", specify the short subscription name you noted before on the Google Cloud Console (note: do NOT use the full-blown subscription name made of project/PROJECT_ID/subscriptions/SUBSCRIPTION_ID). Just pick the Subscription ID from the Google Cloud Console).
- Click on "Save Integration", and make sure the Elastic Agent gets the updated policy.

### Troubleshooting

If you don't see Audit logs showing up, check the Agent logs to see if there are errors.

Common error types:

- Missing roles in the Service Account
- Misconfigured settings, like "Project Id", "Topic" or "Subscription Name" fields

#### Missing Roles in the Service Account

If your Service Account (SA) does not have the required roles, you might find errors like this one in the `elastic_agent.filebeat` dataset:

```text
failed to subscribe to pub/sub topic: failed to check if subscription exists: rpc error: code = PermissionDenied desc = User not authorized to perform this action.
```

Solution: make sure your SA has all the required roles.

#### Misconfigured Settings

If you specify the wrong "Topic field" or "Subscription Name", you might find errors like this one in the `elastic_agent.filebeat` dataset:

```text
[elastic_agent.filebeat][error] failed to subscribe to pub/sub topic: failed to check if subscription exists: rpc error: code = InvalidArgument desc = Invalid resource name given (name=projects/project/subscriptions/projects/project/subscriptions/non-existent-sub). Refer to https://cloud.google.com/pubsub/docs/admin#resource_names for more information.
```

Solution: double check the integration settings.

## Logs

### Audit

The `audit` dataset collects audit logs of administrative activities and accesses within your Google Cloud resources.

{{fields "audit"}}

{{event "audit"}}

### Firewall

The `firewall` dataset collects logs from Firewall Rules in your Virtual Private Cloud (VPC) networks.

{{fields "firewall"}}

{{event "firewall"}}

### VPC Flow

The `vpcflow` dataset collects logs sent from and received by VM instances, including instances used as GKE nodes.

{{fields "vpcflow"}}

{{event "vpcflow"}}

### DNS

The `dns` dataset collects queries that name servers resolve for your Virtual Private Cloud (VPC) networks, as well as queries from an external entity directly to a public zone.

{{fields "dns"}}

{{event "dns"}}
