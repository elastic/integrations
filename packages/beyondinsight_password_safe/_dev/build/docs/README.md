# BeyondInsight and Password Safe Integration

## Overview

The BeyondInsight and Password Safe integration enables real-time monitoring of
privileged account access, session recordings, and password checkout patterns to
help security teams maintain compliance and quickly identify potential privilege
abuse through BeyondTrust's Just-in-Time (JIT) privileged access management capabilities.

### Compatibility

- BeyondInsight/Password Safe 25.x

### How it works

The integration uses BeyondTrust's REST APIs to collect data through
authenticated API calls. It establishes sessions using API key authentication
and retrieves data from multiple API endpoints:

1. **Authentication**: Uses the PS-Auth header with an API key, username, and optional password
2. **Data Collection**: Polls multiple API endpoints at configurable intervals:
   - `/ManagedAccounts` - Managed account information
   - `/ManagedSystems` - Managed system configurations
   - `/Sessions` - Active and historical session data
   - `/UserAudits` - User audit logs and activity tracking
   - `/Workgroups` - List available workgroups
   - `/Workgroups/{id}/Assets` - Asset inventory from workgroups
3. **Processing**: Transforms the data using ingest pipelines for ECS field mappings

## What data does this integration collect?

The BeyondInsight and Password Safe integration collects log messages of the
following types:

* **`asset`** Provides asset inventory data from BeyondInsight workgroups,
  including servers, workstations, and network devices with their system
  details, IP addresses, and organizational metadata.
* **`managedaccount`** Provides managed account information including local and
  Active Directory accounts with their security policies, password change
  schedules, access permissions, and application associations.
* **`managedsystem`** Provides a list of systems managed by Password Safe.
* **`session`** Provides session monitoring data including active and completed
  privileged access sessions with status tracking, duration metrics, protocol
  information, and archive status for compliance auditing.
* **`useraudit`** Provides user audit activity tracking including
  user actions, authentication events, system access, and administrative
  operations with context about usernames, IP addresses, and timestamps
  for security monitoring and compliance.

### Supported use cases

This integration enables several security and compliance use cases:

**Asset Management and Visibility**
- Maintain inventory of all managed assets across workgroups
- Track asset configurations, IP addresses, and system specifications
- Monitor asset lifecycle from creation to updates

**Privileged Access Monitoring**
- Real-time monitoring of privileged account activities and session recordings
- Track password checkouts, session durations, and access patterns
- Identify potential privilege abuse or unauthorized access attempts

**Compliance and Auditing**
- Generate detailed audit trails for privileged access activities
- Track user actions, login patterns, and system changes

**Security Operations**
- Correlate privileged access events with security incidents
- Detect anomalous session behaviors or access patterns
- Monitor managed system and account configurations for unauthorized changes

## What do I need to use this integration?

You must install Elastic Agent. For more details, check the Elastic
Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).
You can install only one Elastic Agent per host.

The Elastic Agent uses the CEL (Common Expression Language) input to collect data
from BeyondTrust's REST APIs and ships the data to Elastic, where the events will
then be processed via the integration's ingest pipelines.

## How do I deploy this integration?

### Configure API Registration

To configure the BeyondInsight and Password Safe integration, a BeyondInsight
administrator must
[create an API registration](https://docs.beyondtrust.com/bips/docs/configure-api)
and provide an API key, username, and (optionally) a password for authentication.

**Steps to create an API registration:**

1. Log in to BeyondInsight with administrator privileges
2. Navigate to `Configuration > General > API Registrations`
3. Enter a name for the registration
4. Click `Create New API Registration`
5. Configure authentication options:
    - **User Password Required**: Enable if you want to require a password in the authorization header
    - **Client Certificate Required**: Leave disabled for this integration
6. Add authentication rules with the IP address(es) of your Elastic Agent host(s)
7. Click `Create Rule`

BeyondInsight generates a unique API key for the registration. Use this API key
along with a valid username (and password if required) to configure the
integration. The integration does not use OAuth authentication.

### Validation

1. Open the Discover page in Kibana.
2. Query for `event.module:beyondinsight_password_safe`.
3. Expand the time range to view data from the last 90 days.
4. Click on the `data_stream.dataset` field from the "Available fields" on the left hand panel.
5. This will display a list of the datasets from this integration that have reported data.

## Troubleshooting

For help with Elastic ingest tools,
check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Scaling

For more information on architectures that can be used for scaling this
integration, check
the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures)
documentation.

## Reference

### asset

Provides asset inventory data collected from BeyondInsight workgroups using
the [Workgroups Assets API][api_workgroups_assets]. This data stream retrieves
asset information from all workgroups, including servers, workstations,
databases, and network devices.

**Data Collection Process:**
1. Authenticates using the [SignAppin API][api_auth]
2. Retrieves all available [workgroups][api_workgroups]
3. Iterates through each workgroup to collect asset inventories
4. Handles pagination automatically to ensure complete data collection
5. Stores the asset documents that have changed in any way since the last poll.

Filter asset documents using `data_stream.dataset:"beyondinsight_password_safe.asset"`.

{{fields "asset"}}

**Sample event**

{{event "asset"}}

### managedaccount

Provides managed account information collected from BeyondTrust using
the [ManagedAccounts API][api_managedaccounts]. This data stream retrieves
detailed information about user accounts managed by Password Safe, including
local accounts, Active Directory accounts, database accounts, and application
accounts.

**Data Collection Process:**
1. Authenticates using the [SignAppin API][api_auth]
2. Retrieves managed account configurations with pagination support
3. Stores the managed account documents that have changed in any way since the last poll.

Filter managed account documents using `data_stream.dataset:"beyondinsight_password_safe.managedaccount"`.

{{fields "managedaccount"}}

**Sample event**

{{event "managedaccount"}}

### managedsystem

Provides managed system configurations collected from BeyondTrust using
the [ManagedSystems API][api_managedsystems]. This data stream retrieves
information about all systems managed by Password Safe, including assets,
databases, directories, and cloud platforms.

**Data Collection Process:**
1. Authenticates using the [SignAppin API][api_auth]
2. Retrieves managed system configurations with pagination support
3. Stores the managed system documents that have changed in any way since the last poll.

Filter managed system documents using `data_stream.dataset:"beyondinsight_password_safe.managedsystem"`.

{{fields "managedsystem"}}

**Sample event**

{{event "managedsystem"}}

### session

Provides session monitoring data collected from BeyondTrust using
the [Sessions API][api_sessions]. This data stream captures information about
all privileged access sessions, including both active and completed sessions for
security monitoring and compliance auditing.

**Data Collection Process:**
1. Authenticates using the [SignAppin API][api_auth]
2. Retrieves session data for monitored systems (API returns up to 100,000 sessions)
3. Stores the session documents that have changed in any way since the last poll.

Filter session documents using `data_stream.dataset:"beyondinsight_password_safe.session"`.

{{fields "session"}}

**Sample event**

{{event "session"}}

### useraudit

Provides user audit activity tracking collected from BeyondTrust using
the [UserAudits API][api_useraudits]. This data stream captures information
about user activities within the BeyondInsight and Password Safe environment,
providing critical visibility for security monitoring, compliance auditing, and
incident investigation.

**Data Collection Process:**
1. Authenticates using the [SignAppin API][api_auth]
2. Uses time-window based queries to efficiently collect only new audit events since the last poll
3. Maintains a high-water mark timestamp to prevent data duplication
4. Handles pagination automatically to ensure complete audit trail collection

Filter user audit documents using `data_stream.dataset:"beyondinsight_password_safe.useraudit"`.

{{fields "useraudit"}}

**Sample event**

{{event "useraudit"}}

### Inputs used

- [Common Expression Language (CEL)](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration uses the following APIs:
* [`/BeyondTrust/api/public/v3/Auth/SignAppin`][api_auth]
* [`/BeyondTrust/api/public/v3/ManagedAccounts`][api_managedaccounts]
* [`/BeyondTrust/api/public/v3/ManagedSystems`][api_managedsystems]
* [`/BeyondTrust/api/public/v3/Sessions`][api_sessions]
* [`/BeyondTrust/api/public/v3/UserAudits`][api_useraudits]
* [`/BeyondTrust/api/public/v3/Workgroups`][api_workgroups]
* [`/BeyondTrust/api/public/v3/Workgroups/{id}/Assets`][api_workgroups_assets]

[api_auth]: https://docs.beyondtrust.com/bips/docs/api#post-authsignappin
[api_managedaccounts]: https://docs.beyondtrust.com/bips/docs/password-safe-apis#get-managedaccounts
[api_managedsystems]: https://docs.beyondtrust.com/bips/docs/password-safe-apis#get-managedsystems
[api_sessions]: https://docs.beyondtrust.com/bips/docs/password-safe-apis#get-sessions
[api_useraudits]: https://docs.beyondtrust.com/bips/docs/beyondinsight-apis#get-useraudits
[api_workgroups]: https://docs.beyondtrust.com/bips/docs/beyondinsight-apis#workgroups-1
[api_workgroups_assets]: https://docs.beyondtrust.com/bips/docs/beyondinsight-apis#get-workgroupsworkgroupidassets
