# Cisco Duo

The Cisco Duo integration collects and parses data from the [Cisco Duo Admin APIs](https://duo.com/docs/adminapi). The Duo Admin API provides programmatic access to the administrative functionality of Duo Security's two-factor authentication platform.

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Compatibility

This module has been tested against Cisco Duo `Core Authentication Service: D224.13` and `Admin Panel: D224.18`

## Requirements

In order to ingest data from the Cisco Duo Admin API you must:
- Have a the Cisco Duo administrator account with **Owner** role [Sign up](https://signup.duo.com/)
- Sign in to [Duo Admin Panel](https://admin.duosecurity.com/login)
- Go through following tabs **Application > Protect an Application > Admin API > Protect**
- Now you will find your **Hostname**, **Integration key** and **Secret key** which will be required while configuring the integration package.
- For this integration you will require **Grant read information** and **Grant read log** permissions.
- Make sure you have whitelisted your IP Address.

More details for each step can be found at [First steps](https://duo.com/docs/adminapi#first-steps).

## Data streams

The Cisco Duo integration collects logs for the following types of events.

- [**Activity Logs**](https://duo.com/docs/adminapi#activity-logs)
- [**Administrator Logs**](https://duo.com/docs/adminapi#administrator-logs)
- [**Authentication Logs**](https://duo.com/docs/adminapi#authentication-logs)
- [**Offline Enrollment Logs**](https://duo.com/docs/adminapi#offline-enrollment-logs)
- [**Summary**](https://duo.com/docs/adminapi#retrieve-summary)
- [**Telephony Logs**](https://duo.com/docs/adminapi#telephony-logs)
- [**Telephony Logs (legacy)**](https://duo.com/docs/adminapi#telephony-logs-(legacy-v1))
- [**Trust Monitor**](https://duo.com/docs/adminapi#trust-monitor)

## V2 Handlers

Cisco Duo has implemented v2 handlers for some endpoints. In these cases, the API v1 handler remains supported, but will be limited or deprecated in the future.

From data streams listed above, v2 handlers are supported for Activity, Authentication and Telephony Logs at the moment. It is recommended to migrate data streams to the v2 endpoints when they become available.

## Configuration

The following considerations should be taken into account when configuring the integration.

- Interval has to be greater or equal than `1m`.
- The Duo Admin API retrieves records from the last 180 days up to as recently as two minutes before the API request. Consider this when configuring the `Initial interval` parameter for the v2 API endpoints, as it doesn't support `d` as a suffix, its maximum value is `4320h` which corresponds to that 180 days.
- For v2 API endpoints, a new parameter `limit` has been added to control the number of records per response. Default value is 100 and can be incresead until 1000.
- Larger values of interval might cause delay in data ingestion.

## Logs

### Activity

This is the `activity` dataset.

{{event "activity"}}

{{fields "activity"}}

### Administrator

This is the `admin` dataset.

{{event "admin"}}

{{fields "admin"}}

### Authentication

This is the `auth` dataset.

{{event "auth"}}

{{fields "auth"}}

### Offline Enrollment

This is the `offline_enrollment` dataset.

{{event "offline_enrollment"}}

{{fields "offline_enrollment"}}

### Summary

This is the `summary` dataset.

{{event "summary"}}

{{fields "summary"}}

### Telephony

This is the `telephony` dataset.

{{event "telephony"}}

{{fields "telephony"}}

### Telephony v2

This is the `telephony_v2` dataset.

{{event "telephony_v2"}}

{{fields "telephony_v2"}}

### Trust Monitor

This is the `trust_monitor` dataset.

{{event "trust_monitor"}}

{{fields "trust_monitor"}}
