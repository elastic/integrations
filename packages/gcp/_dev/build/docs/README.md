# Google Cloud Platform Integration

The Google Cloud integration collects and parses Google Cloud [Audit Logs](https://cloud.google.com/logging/docs/audit), [VPC Flow Logs](https://cloud.google.com/vpc/docs/using-flow-logs), [Firewall Rules Logs](https://cloud.google.com/vpc/docs/firewall-rules-logging) and [Cloud DNS Logs](https://cloud.google.com/dns/docs/monitoring) that have been exported from Cloud Logging to a Google Pub/Sub topic sink and collects Google Cloud [metrics](https://cloud.google.com/monitoring/api/metrics_gcp) and metadata from Google Cloud [Monitoring](https://cloud.google.com/monitoring/docs).

## Authentication

To use this Google Cloud Platform (GCP) integration, you need to set up a
*Service Account* with a *Role* and a *Service Account Key* to access data on
your GCP project.

### Service Account

First, you need to [create a Service Account](https://cloud.google.com/iam/docs/creating-managing-service-accounts). A Service Account (SA) is a particular type of Google account intended to represent a non-human user who needs to access the GCP resources.

The Elastic Agent uses the SA to access data on Google Cloud Platform using the Google APIs.

If you haven't already, this might be a good moment to check out the [best
practices for securing service
accounts](https://cloud.google.com/iam/docs/best-practices-for-securing-service-accounts)
guide.

### Role

You need to grant your Service Account (SA) access to Google Cloud Platform
resources by assigning a role to the account. In order to assign minimal
privileges, create a custom role that has only the privileges required by Agent.
Those privileges are:

- `compute.instances.list` (required for GCP Compute instance metadata collection) **
- `monitoring.metricDescriptors.list`
- `monitoring.timeSeries.list`
- `pubsub.subscriptions.consume`
- `pubsub.subscriptions.create` *
- `pubsub.subscriptions.get`
- `pubsub.topics.attachSubscription` *

\* Only required if Agent is expected to create a new subscription. If you
create the subscriptions yourself you may omit these privileges.
\*\* Only required if corresponding collection will be enabled.

After you have created the custom role, assign the role to your service account.

### Service Account Keys

Now, with your brand new Service Account (SA) with access to Google Cloud Platform (GCP) resources, you need some credentials to associate with it: a Service Account Key.

From the list of SA:

1. Click the one you just created to open the detailed view.
2. From the Keys section, click "Add key" > "Create new key" and select JSON as the type.
3. Download and store the generated private key securely (remember, the private key can't be recovered from GCP if lost).

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
- If you created a new topic, you must remember to go to that topic and create a subscription for it. A subscription directs messages on a topic to subscribers. Note the "Subscription ID", as it will need to be entered in the "Subscription name" field in the integration settings.
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

Start working on your query using the Google Cloud [Logs Explorer](https://console.cloud.google.com/logs/query), so you can preview and pinpoint the exact log types you want to forward to your Elastic Stack.

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

## Metrics Collection Configuration

With a properly configured Service Account and the integration setting in place, it's time to start collecting some metrics.

### Requirements

No additional requirement is needed to collect metrics.

### Troubleshooting

If you don't see metrics showing up, check the Agent logs to see if there are errors.

Common error types:

- Period is lower than 60 seconds
- Missing roles in the Service Account
- Misconfigured settings, like "Project Id"

#### Period is lower than 60 seconds

Usual minimum collection period for GCP metrics is 60 seconds. Any value lower than that cause an error when retrieving the metric metadata. If an error happens, the affected metric is skipped at the metric collection stage, resulting in no data being sent.

#### Missing Roles in the Service Account

If your Service Account (SA) does not have required roles, you might find errors related to accessing GCP resources.

To check you may add `Monitoring Viewer` and `Compute Viewer` roles (built-in GCP roles) to your SA. These roles contain the permission added in the previous step and expand them with additional permissions. You can analyze additional missing permissions from the GCP Console > IAM > clicking on the down arrow near the roles on the same line of your SA > View analyzed permissions. From the shown table you can check which permissions from the role the SA is actively using. They should match what you configured in your custom role.

#### Misconfigured Settings

If you specify a wrong setting you will probably find errors related to missing GCP resources.

Make sure the settings are correct and the SA has proper permissions for the given "Project Id".

## Logs

### Audit

The `audit` dataset collects audit logs of administrative activities and accesses within your Google Cloud resources.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "audit"}}

{{event "audit"}}

### Firewall

The `firewall` dataset collects logs from Firewall Rules in your Virtual Private Cloud (VPC) networks.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "firewall"}}

{{event "firewall"}}

### VPC Flow

The `vpcflow` dataset collects logs sent from and received by VM instances, including instances used as GKE nodes.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "vpcflow"}}

{{event "vpcflow"}}

### DNS

The `dns` dataset collects queries that name servers resolve for your Virtual Private Cloud (VPC) networks, as well as queries from an external entity directly to a public zone.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "dns"}}

{{event "dns"}}

### Loadbalancing Logs

The `loadbalancing_logs` dataset collects logs of the requests sent to and handled by GCP Load Balancers.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "loadbalancing_logs"}}

{{event "loadbalancing_logs"}}

## Metrics

### Billing

The `billing` dataset collects GCP Billing information from Google Cloud BigQuery daily cost detail table.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "billing"}}

{{event "billing"}}

### Compute

The `compute` dataset is designed to fetch metrics for [Compute Engine](https://cloud.google.com/compute/) Virtual Machines in Google Cloud Platform.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "compute"}}

{{event "compute"}}

### Dataproc

The `dataproc` dataset is designed to fetch metrics from [Dataproc](https://cloud.google.com/dataproc/) in Google Cloud Platform.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "dataproc"}}

{{event "dataproc"}}

### Firestore

The `firestore` dataset fetches metrics from [Firestore](https://cloud.google.com/firestore/) in Google Cloud Platform.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "firestore"}}

{{event "firestore"}}

### GKE

The `gke` dataset is designed to fetch metrics from [GKE](https://cloud.google.com/kubernetes-engine) in Google Cloud Platform.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "gke"}}

{{event "gke"}}

### Loadbalancing Metrics

The `loadbalancing_metrics` dataset is designed to fetch HTTPS, HTTP, and Layer 3 metrics from [Load Balancing](https://cloud.google.com/load-balancing/) in Google Cloud Platform.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "loadbalancing_metrics"}}

{{event "loadbalancing_metrics"}}

### Redis

The `redis` dataset is designed to fetch metrics from [GCP Memorystore](https://cloud.google.com/memorystore/) for [Redis](https://cloud.google.com/memorystore/docs/redis/redis-overview) in Google Cloud Platform.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "redis"}}

{{event "redis"}}

### Storage

The `storage` dataset fetches metrics from [Storage](https://cloud.google.com/storage/) in Google Cloud Platform.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "storage"}}

{{event "storage"}}
