# BitDefender Integration

[BitDefender GravityZone](https://www.bitdefender.com/business/products/security-products.html) supports SIEM integration using "push notifications", which are JSON messages sent via HTTP POST to a HTTP or HTTPS endpoint, which this integration can consume.

This integration additionally provides:
1. Collection of push notification configuration via API polling, which includes the "state" of the push notification service on the BitDefender GravityZone server, e.g. indicating if it is currently enabled or disabled. This is useful as the state may change to disabled (value of 0) for unknown reasons and you may wish to alert on this event.
2. Collection of push notification statistics via API polling, which includes the number of events sent, and counters for errors of different types, which you may wish to use to troubleshoot lost push notification events and for alerting purposes.
3. Support for multiple instances of the integration, which may be needed for MSP/MSSP scenarios where multiple BitDefender GravityZone tenants exist.
4. BitDefender company ID to your own company name/description mapping, in order to determine to which tenant the event relates to in a human friendly way. This is very useful for MSP/MSSP environments or for large organisations with multiple sub-organisations.

This allows you to search, observe and visualize the BitDefender GravityZone events through Elastic, trigger alerts and monitor the BitDefender GravityZone Push Notification service for state and errors.

For more information about BitDefender GravityZone, refer to [BitDefender GravityZone](https://www.bitdefender.com/business/products/security-products.html) and read the  [Public API - Push](https://www.bitdefender.com/business/support/en/77209-135318-push.html) documentation.

## Compatibility

This integration supports BitDefender GravityZone, which is the business oriented product set sold by BitDefender.

BitDefender products for home users are not supported.

The package collects BitDefender GravityZone push notification transported events sent in `jsonrpc`, `qradar`, or `splunk` format.

The `jsonrpc` format is recommended default but the ingest pipeline will attempt to detect if `qradar` or `splunk` format events have been received and process them accordingly.

The integration can also collect the push notification configuration and statistics by polling the BitDefender GravityZone API.

## Configuration

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**
2. In "Search for integrations" search bar type **GravityZone**
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
    "serviceType": "jsonrpc",
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

## Data Stream

### Log Stream Push Notifications

The BitDefender GravityZone events dataset provides events from BitDefender GravityZone push notifications that have been received.

All BitDefender GravityZone log events are available in the `bitdefender_gravityzone.events` field group.

{{fields "push_notifications"}}

{{event "push_notifications"}}

### Log Stream Push Notification Configuration

The BitDefender GravityZone push notification configuration dataset provides configuration state collected from the BitDefender GravityZone API.

This includes the status of the push notification configuration, which may be indicative of the push notification service being disabled. Alerting based on this may be desirable.

All BitDefender GravityZone push notification configuration states are available in the `bitdefender.push.configuration` field group.

{{fields "push_configuration"}}

{{event "push_configuration"}}

### Log Stream Push Notification Statistics

The BitDefender GravityZone push notification statistics dataset provides statistics collected from the BitDefender GravityZone API.

This includes information about errors and HTTP response codes that the push notification service has received when sending push notifications, which may be indicative of failures to deliver push notifications resulting in missing events. Alerting based on this may be desirable.

All BitDefender GravityZone push notification statistics are available in the `bitdefender.push.stats` field group.

{{fields "push_statistics"}}

{{event "push_statistics"}}
