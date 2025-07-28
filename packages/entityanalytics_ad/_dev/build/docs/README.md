# Active Directory Entity Analytics

This Active Directory Entity Analytics integration allows users to securely stream User Entities data to Elastic Security via the Active Directory LDAP look-ups. When integrated with Elastic Security, this valuable data can be leveraged within Elastic for risk-scoring scenarios (e.g., context enrichments) and detecting advanced analytics (UBA) use cases.

## Data streams

The Active Directory Entity Analytics integration collects one type of data: user.

- **User** is used to retrieve all user entries available from an Active Directory server.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### Collect data from Active Directory

1. Obtain the LDAP username, for example `CN=Administrator,CN=Users,DC=testserver,DC=local` and password, and LDAP host address for the Active Directory server that you will be collecting data from.
2. Determine the Base DN for the directory to be used, for example `CN=Users,DC=testserver,DC=local`.

### Enabling the integration in Elastic:

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **Active Directory Entity Analytics**.
3. Select the **Active Directory Entity Analytics** integration and add it.
4. While adding the integration, add the user, host and base DN details obtained above.
5. Save the integration.

## Usage

The Active Directory provider periodically contacts the server, retrieving updates for users, updates its internal cache of user metadata, and ships updated user metadata to Elasticsearch.

Fetching and shipping updates occurs in one of two processes: **full synchronizations** and **incremental updates**. Full synchronizations will send the entire list of users in state, along with write markers to indicate the start and end of the synchronization event. Incremental updates will only send data for changed users during that event. Changes on a user can come in many forms, whether it be a change to the user’s metadata, or a user was added or deleted. By default, full synchronizations occur every 24 hours and incremental updates occur every 15 minutes. These intervals may be customized to suit your use case.

## Logs reference

### User

This is the `User` dataset.

#### Example

{{event "user"}}

{{fields "user"}}
