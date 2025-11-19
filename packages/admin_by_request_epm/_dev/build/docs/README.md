# Admin By Request EPM integration

The Elastic integration for [Admin By Request EPM](https://www.adminbyrequest.com/en/endpoint-privilege-management) enables real-time monitoring and analysis of audit logging of privilege elevations, software installations and administrative actions through user portal. This integration collects, processes, and visualizes audit logs and events to enhance security posture, compliance, and operational efficiency.

## What data does this integration collect?

- **`auditlog`**: Provides audit data that includes elevation requests, approvals, application installations, and scan results.
- [Auditlog](https://www.adminbyrequest.com/en/docs/auditlog-api) are records generated when user takes action such as installing a software, running an application with admin privileges, requesting for admin session, approval or denial of requests and scan results.
- This data stream leverages the Admin By Request EPM API [`/auditlog/delta`](https://www.adminbyrequest.com/en/docs/auditlog-api#:~:text=throttle%20your%20account-,Delta%20Data,-To%20avoid%20having) endpoint to retrieve data.

- **`events`**: Provides system security events and administrative changes, including group modifications, policy changes and security violations. This allows tracking of administrative activities and security-critical events. Some events have corresponding audit log entries.
- [Events](https://www.adminbyrequest.com/en/docs/events-api) are records that are generated on various actions done by users and administrators. These include group modifications, policy changes, security violations, and other administrative activities.
- This data stream leverages the Admin By Request EPM API [`/events`](https://www.adminbyrequest.com/en/docs/events-api) endpoint to retrieve data.

## What do I need to use this integration?

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

For step-by-step instructions on how to set up an integration, check the [Getting started](docs-content://solutions/observability/get-started/quickstart-monitor-hosts-with-elastic-agent.md).

## Generate an API Key

Log in to the Cloud portal, enable the API access, and set up an API key. Generated API Key is used to access data through APIs. To create an API Key, follow the instructions provided in the [Public API - API Overview](https://www.adminbyrequest.com/en/docs/api-overview) documentation.

## Logs

### Auditlog

Auditlog documents can be found by setting the following filter: 
`event.dataset : "admin_by_request_epm.auditlog"`

{{event "auditlog"}}

    
**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in events documents:

{{fields "auditlog"}}


### Events

Event documents can be found by setting the following filter: 
`event.dataset : "admin_by_request_epm.events"`

{{event "events"}}
    
**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in events documents:

{{fields "events"}}

Events Data stream has field `eventCode` which is a unique identifier for each event type. Refer to the Event Codes table given on the [Events API documentation](https://www.adminbyrequest.com/en/docs/events-api) for more information on event codes.