# authentik

authentik is an IdP (Identity Provider) and SSO (single sign on) that is built with security at the forefront of every piece of code, every feature, with an emphasis on flexibility and versatility.

The authentik integration collects event, group, and user logs using REST API.

## Data streams

The authentik integration collects three types of logs:

- **[Event](https://docs.goauthentik.io/docs/developer-docs/api/reference/events-events-list)**                         
- **[Group](https://docs.goauthentik.io/docs/developer-docs/api/reference/core-groups-list)**                           
- **[User](https://docs.goauthentik.io/docs/developer-docs/api/reference/core-users-list)**                             

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### To collect data from the authentik API:

- Log in to your authentik instance to obtain your API Token. Open the **Admin interface** and navigate to **Directory > Tokens and App passwords**. There, create an API Token, then save and copy this token.

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Authentik`.
3. Select the "authentik" integration from the search results.
4. Select "Add authentik" to add the integration.
5. Add all the required integration configuration parameters, including API Token, Interval and Page Size to enable data collection.
6. Select "Save and continue" to save the integration.

## Logs reference

### Event

This is the `event` dataset.

#### Example

{{event "event"}}

{{fields "event"}}

### Group

This is the `group` dataset.

#### Example

{{event "group"}}

{{fields "group"}}

### User

This is the `user` dataset.

#### Example

{{event "user"}}

{{fields "user"}}
