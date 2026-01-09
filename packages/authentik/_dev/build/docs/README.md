# authentik

authentik is an IdP (Identity Provider) and SSO (single sign on) that is built with security at the forefront of every piece of code, every feature, with an emphasis on flexibility and versatility.

The authentik integration collects event, group, and user logs using REST API.

## What data does this integration collect?

The authentik integration collects three types of logs:

- **[Event](https://docs.goauthentik.io/docs/developer-docs/api/reference/events-events-list)**                         
- **[Group](https://docs.goauthentik.io/docs/developer-docs/api/reference/core-groups-list)**                           
- **[User](https://docs.goauthentik.io/docs/developer-docs/api/reference/core-users-list)**                             

## What do I need to use this integration?

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### Collect data from the authentik API

1. Log in to your authentik instance to obtain your API Token. 
2. Open the **Admin interface** and navigate to **Directory > Tokens and App passwords**. 
3. Create the API Token, save and copy it somewhere.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **Authentik**.
3. Select the **Authentik** integration and add it.
4. Add all the required integration configuration parameters, including API Token, Interval and Page Size to enable data collection.
5. Save the integration.

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
