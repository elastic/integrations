# Active Directory Entity Analytics

This Active Directory Entity Analytics integration allows users to securely stream User Entities data to Elastic Security via the Active Directory LDAP look-ups. When integrated with Elastic Security, this valuable data can be leveraged within Elastic for risk-scoring scenarios (e.g., context enrichments) and detecting advanced analytics (UBA) use cases.

## Data streams

The Active Directory Entity Analytics integration collects one type of data: user.

**User** is used to retrieve all user entries available from an Active Directory server.

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data using Entity Analytics Input and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.14.0**.

## Setup

### To collect data from Active Directory, follow the below steps:

- Obtain the LDAP username, e.g. `CN=Administrator,CN=Users,DC=testserver,DC=local` and password, and LDAP host address for the Active Directory server that you will be collecting data from.
- Determine the Base DN for the directory to be used, e.g. `CN=Users,DC=testserver,DC=local`.

### Enabling the integration in Elastic:

1. In Kibana, go to Management > Integrations.
2. In the "Search for integrations" search bar, type Active Directory Entity Analytics.
3. Click on the "Active Directory Entity Analytics" integration from the search results.
4. Click on the Add Active Directory Entity Analytics Integration button to add the integration.
5. While adding the integration, add the user, host and base DN details obtained above.
6. Save the integration by adding other necessary parameters.

## Usage

The Active Directory provider periodically contacts the server, retrieving updates for users, updates its internal cache of user metadata, and ships updated user metadata to Elasticsearch.

Fetching and shipping updates occurs in one of two processes: **full synchronizations** and **incremental updates**. Full synchronizations will send the entire list of users in state, along with write markers to indicate the start and end of the synchronization event. Incremental updates will only send data for changed users during that event. Changes on a user can come in many forms, whether it be a change to the user’s metadata, or a user was added or deleted. By default, full synchronizations occur every 24 hours and incremental updates occur every 15 minutes. These intervals may be customized to suit your use case.

## Logs reference

### User

This is the `User` dataset.

#### Example

{{event "user"}}

{{fields "user"}}
