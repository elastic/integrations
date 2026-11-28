# BitDefender Integration

## Overview

[BitDefender GravityZone](https://www.bitdefender.com/business/products/security-products.html) supports SIEM integration using "push notifications", which are JSON messages sent via HTTP POST to a HTTP or HTTPS endpoint, which this integration can consume.

This integration additionally provides:
1. Collection of push notification configuration via API polling, which includes the "state" of the push notification service on the BitDefender GravityZone server, e.g. indicating if it is currently enabled or disabled. This is useful as the state may change to disabled (value of 0) for unknown reasons and you may wish to alert on this event.
2. Collection of push notification statistics via API polling, which includes the number of events sent, and counters for errors of different types, which you may wish to use to troubleshoot lost push notification events and for alerting purposes.
3. Support for multiple instances of the integration, which may be needed for MSP/MSSP scenarios where multiple BitDefender GravityZone tenants exist.
4. BitDefender company ID to your own company name/description mapping, in order to determine to which tenant the event relates to in a human friendly way. This is very useful for MSP/MSSP environments or for large organisations with multiple sub-organisations.
5. GravityZone Public API polling for EDR/XDR incidents and individual incident alerts.

This allows you to search, observe and visualize BitDefender GravityZone events and incidents through Elastic, trigger alerts, and monitor the BitDefender GravityZone Push Notification service for state and errors.

For more information about BitDefender GravityZone, refer to [BitDefender GravityZone](https://www.bitdefender.com/business/products/security-products.html) and refer to the [Public API - Push](https://www.bitdefender.com/business/support/en/77209-135318-push.html) documentation.

## Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

### Compatibility

This integration supports BitDefender GravityZone, which is the business oriented product set sold by BitDefender.

BitDefender products for home users are not supported.

The package collects BitDefender GravityZone push notification transported events sent in `jsonrpc`, `qradar`, or `splunk` format.

The `jsonrpc` format is recommended default, but the ingest pipeline will attempt to detect if `qradar` or `splunk` format events have been received and process them accordingly.

The integration can also collect the push notification configuration and statistics and poll higher-level security incidents from the BitDefender GravityZone Public API.

Public API polling in this integration targets GravityZone Cloud. GravityZone On-Premises has a different API surface, authentication model, and service-specific paths and is not supported by the Public API polling data streams.

## How do I deploy this integration?

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**.
2. In "Search for integrations" search bar type **GravityZone**.
3. Click on "BitDefender GravityZone" integration from the search results.
4. Click on **Add BitDefender GravityZone** button to add BitDefender GravityZone integration.

![Example Integration Configuration](../img/bitdefender-integration-configuration-1.png)

![Example Integration Configuration](../img/bitdefender-integration-configuration-2.png)

### Create a BitDefender GravityZone API key that can configure a push notification service

The vendor documentation is available [here](https://www.bitdefender.com/business/support/en/77211-125280-getting-started.html#UUID-e6befdd4-3eb1-4b6e-cc6c-19bdd16847b4_section-idm4640169987334432655171029621). However, at the time of writing this is out of date and the screenshots the vendor provides do not accurately describe what you will need to do.

The API key needed to configure push notifications, and collection push notification configuration state and statistics, is typically configured within the BitDefender GravityZone cloud portal [here](https://cloud.gravityzone.bitdefender.com/)

Bear in mind the API key will be associated to the account you create it from. A named human account may not be desirable, e.g. you may wish to  (probably should) create API keys for functions such as push notifications under a non-human/software service account that will never retire or be made redundant.

Navigate to your account details within the GravityZone portal. If you have sufficient privileges you will see the "API keys" section near the bottom of the page. Click "Add" here.

![Example Configuration 1](../img/bitdefender-gravityzone-api-key-1.png)

Give the API key a description and tick the "Event Push Service API" box at minimum.

NOTE: If you intend to use the API key for other API calls you may need to tick other boxes.

![Example Configuration 2](../img/bitdefender-gravityzone-api-key-2.png)

Click the Key value that is shown in blue.

![Example Configuration 3](../img/bitdefender-gravityzone-api-key-3.png)

Click the clipboard icon to copy the API key to your PC's clipboard.

![Example Configuration 4](../img/bitdefender-gravityzone-api-key-4.png)

### Create an API key for Public API polling

The Public API polling data streams support either of these authentication types:

- A Service API key, configured with `x_api_key`, from **Accounts → Service API keys**. Enable only the API areas required by the selected data streams. Service API keys are independent of human accounts, expire after at most one year, and do not support the Event Push Service API.
- A Personal API key, configured with `basic`, from the account menu under **API keys**. Personal API keys are required for the existing Push API streams.

Copy the exact Control Center API Access URL from the account menu under **Control Center API**. The URL normally ends in `/api`. GravityZone uses multiple regional instances, including `https://cloudgz.gravityzone.bitdefender.com/api`, `https://cloud.gravityzone.bitdefender.com/api`, and `https://cloudap.gravityzone.bitdefender.com/api`. An API key is valid only on the Control Center instance where it was created. If GravityZone reports an invalid API key, verify the Access URL before replacing the key.

For partner or MSP collection, optionally set the target company ID. The integration places that ID in the method-specific request field required by each API.

If Push and Public API polling require different key types or permissions, create separate integration policies and enable only the relevant data streams in each policy.

The Public API data streams require the corresponding GravityZone API permissions and product licenses:

- Incidents: **Incidents API** and an EDR/XDR-capable subscription.

Selecting an API area when creating a key does not grant the corresponding product license or user rights.

GravityZone rate limits vary by API method and tenant. A throttled request returns HTTP `429` and can include a `Retry-After` header. The integration retries throttled requests. Each polling cycle fetches every paginated response page for the enabled stream:

- Incidents runs paginated `getIncidentsList` requests for the window and then resolves full details with `getIncidentsByIds` in batches of up to 10 incident IDs per request.

### Creating the push notification configuration via BitDefender GravityZone API

The BitDefender documentation for how to do this is [here](https://www.bitdefender.com/business/support/en/77209-135319-setpusheventsettings.html)

You should use the `jsonrpc` format option.

An example using cURL:

```
curl --location --request POST 'https://cloud.gravityzone.bitdefender.com/api/v1.0/jsonrpc/push' \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--header 'Authorization: Basic TE9MX05JQ0VfVFJZOgo=' \
--data-raw '{
  "id": 1,
  "jsonrpc": "2.0",
  "method": "setPushEventSettings",
  "params": {
    "status": 1,
    "serviceType": "jsonRPC",
    "serviceSettings": {
      "authorization": "secret value",
      "requireValidSslCertificate": true,
      "url": "https://your.webhook.receiver.domain.tld/bitdefender/push/notification"
    },
    "subscribeToCompanies": [
      "COMPANY IDS HERE IF YOU HAVE A MULTI TENANT ENVIRONMENT",
      "AND YOU WANT TO LIMIT THE SUBSCRIPTION TO ONLY SOME COMPANIES",
      "OTHERWISE DELETE THE ENTIRE subscribeToCompanies NODE TO GET EVERYTHING"
    ],
    "subscribeToEventTypes": {
      "adcloud": true,
      "antiexploit": true,
      "aph": true,
      "av": true,
      "avc": true,
      "dp": true,
      "endpoint-moved-in": true,
      "endpoint-moved-out": true,
      "exchange-malware": true,
      "exchange-user-credentials": true,
      "fw": true,
      "hd": true,
      "hwid-change": true,
      "install": true,
      "modules": true,
      "network-monitor": true,
      "network-sandboxing": true,
      "new-incident": true,
      "ransomware-mitigation": true,
      "registration": true,
      "security-container-update-available": true,
      "supa-update-status": true,
      "sva": true,
      "sva-load": true,
      "task-status": true,
      "troubleshooting-activity": true,
      "uc": true,
      "uninstall": true
    }
  }
}'
```

## Dashboards

There are two dashboards available as part of the integration,

"[BitDefender GravityZone] Push Notifications", which provides a summary of push notifications received within the search window.

![Push Notifications Dashboard](./img/bitdefender-dashboard-push-notifications.png)

"[BitDefender GravityZone] Configuration State & Statistics", which provides graphs and other visualisations related push notification service state and statistics available within the search window.

![Configuration State & Statistics Dashboard](./img/bitdefender-dashboard-push-config-and-stats.png)

## Data stream

### Log stream push notifications

The BitDefender GravityZone events dataset provides events from BitDefender GravityZone push notifications that have been received.

All BitDefender GravityZone log events are available in the `bitdefender_gravityzone.events` field group.

{{fields "push_notifications"}}

{{event "push_notifications"}}

### Log stream push notification configuration

The BitDefender GravityZone push notification configuration dataset provides configuration state collected from the BitDefender GravityZone API.

This includes the status of the push notification configuration, which may be indicative of the push notification service being disabled. Alerting based on this may be desirable.

All BitDefender GravityZone push notification configuration states are available in the `bitdefender.push.configuration` field group.

{{fields "push_configuration"}}

{{event "push_configuration"}}

### Log stream push notification statistics

The BitDefender GravityZone push notification statistics dataset provides statistics collected from the BitDefender GravityZone API.

This includes information about errors and HTTP response codes that the push notification service has received when sending push notifications, which may be indicative of failures to deliver push notifications resulting in missing events. Alerting based on this may be desirable.

All BitDefender GravityZone push notification statistics are available in the `bitdefender.push.stats` field group.

{{fields "push_statistics"}}

{{event "push_statistics"}}

### Log stream incidents

The incidents dataset collects changed EDR and XDR incidents and retrieves their complete details, including alert graphs, affected entities, MITRE ATT&CK metadata, status, priority, and analyst notes. Each polling cycle pages through `getIncidentsList` and fetches full incident objects with `getIncidentsByIds` in batches of up to 10 IDs. Parent incident documents use a revision-aware document ID derived from `incidentId` and `lastIncidentChange`, so unchanged boundary overlaps collapse onto the same document while status, action, or severity updates are preserved as new revisions in the append-only data stream.

The same poll emits each object in an incident's `details.alerts` array as a separate document in the `bitdefender.incident_alert` dataset. Individual alert documents include compact parent-incident context and alert-level process, file, network, registry, user, host, and related indicator fields. Alert documents use a revision-aware document ID derived from the parent incident ID, alert ID, and parent incident state so unchanged re-polls deduplicate cleanly without dropping later incident status, action, or severity updates. This fan-out does not make additional GravityZone API requests.

{{fields "incident"}}

{{event "incident"}}

### Log stream incident alerts

The incident alerts dataset contains one document for each endpoint EDR or organization XDR alert embedded in an incident. Enable the incidents data stream to collect both the parent incident and these individual alert documents. Use `data_stream.dataset: bitdefender.incident_alert` to search the alert-level events. Alert titles, identifiers, risk scores, and normalized severities are populated for compatibility with the Elastic Security External Alerts rule.

{{fields "incident_alert"}}
