# Admin By Request EPM integration

The Elastic integration for [Admin By Request EPM](https://www.adminbyrequest.com/en/endpoint-privilege-management) enables real-time monitoring and analysis of audit logging of privilege elevations, software installations and administrative actions through user portal. This integration collects, processes, and visualizes audit logs and events to enhance security posture, compliance, and operational efficiency.

## Data Streams

- **`auditlog`**: Provides audit data that includes elevation requests, approvals, application installations, and scan results.
- [Auditlog](https://www.adminbyrequest.com/en/docs/auditlog-api) are records generated when user takes action such as installing a software, running an application with admin privileges, requesting for admin session, approval or denial of requests and scan results.
- This data stream leverages the Admin By Request EPM API [`/auditlog/delta`](https://www.adminbyrequest.com/en/docs/auditlog-api#:~:text=throttle%20your%20account-,Delta%20Data,-To%20avoid%20having) endpoint to retrieve data.

- **`events`**: Provides system security events and administrative changes, including group modifications, policy changes and security violations. This allows tracking of administrative activities and security-critical events. Some events have corresponding audit log entries.
- [Events](https://www.adminbyrequest.com/en/docs/events-api) are records that are generated on various actions done by users and administrators. These include group modifications, policy changes, security violations, and other administrative activities.
- This data stream leverages the Admin By Request EPM API [`/events`](https://www.adminbyrequest.com/en/docs/events-api) endpoint to retrieve data.

## Requirements

Elastic Agent must be installed. For more details and installation instructions, please refer to the [Elastic Agent Installation Guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

There are several options for installing and managing Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

Please note, there are minimum requirements for running Elastic Agent. For more information, refer to the  [Elastic Agent Minimum Requirements](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html#elastic-agent-installation-minimum-requirements).


### Generate an API Key:

Log in to the portal enable the API access and set up an API key. Generated API Key is used to access data through APIs. 

To create an **API Key** follow the instructions provided in the official documentation:  
[Public API - API Overview](https://www.adminbyrequest.com/en/docs/api-overview).

## Logs

### Auditlog

Auditlog documents can be found by setting the following filter: 
`event.dataset : "admin_by_request_epm.auditlog"`

{{event "auditlog"}}

    
**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in events documents:

{{fields "auditlog"}}


### Events

Event documents can be found by setting the following filter: 
`event.dataset : "admin_by_request_epm.events"`

{{event "events"}}
    
**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in events documents:

{{fields "events"}}

Events Data stream has field `eventCode` which is a unique identifier for each event type. Please refer to the Event Codes table given on the [Events API documentation](https://www.adminbyrequest.com/en/docs/events-api) for more information on event codes.