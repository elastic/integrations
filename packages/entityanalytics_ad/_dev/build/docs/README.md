# Active Directory Entity Analytics

This Active Directory Entity Analytics integration allows users to securely stream User Entities data to Elastic Security via the Active Directory LDAP look-ups. When integrated with Elastic Security, this valuable data can be leveraged within Elastic for risk-scoring scenarios (e.g., context enrichments) and detecting advanced analytics (UBA) use cases.

## Upgrading to v0.15.0 from v0.14 and lower of the integration

In v0.15.0 of the integration the user and device data was split into separate data streams. The data ingested into your index will be the same but you may need to update device searches if you were using them.

**NOTE**: When you upgrade from a version prior to v0.15.0 you will need to reconfigure the integration and enable it due to internal changes in the package. See [Resolve conflicts](https://www.elastic.co/guide/en/fleet/current/upgrade-integration.html#resolve-conflicts) in the Fleet documentation for details.

## Data streams

The Active Directory Entity Analytics integration collects one type of data: user.

- **User** is used to retrieve all user entries available from an Active Directory server.
- **Device** is used to retrieve all device logs available from an Active Directory server.

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

## Sample Events

A user document:

```json
{
    "@timestamp": "2024-02-05T06:37:40.876026-05:00",
    "event": {
        "action": "user-discovered",
    },
    "activedirectory": {
        "id": "CN=Guest,CN=Users,DC=testserver,DC=local",
        "user": {
            "accountExpires": "2185-07-21T23:34:33.709551516Z",
            "badPasswordTime": "0",
            "badPwdCount": "0",
            "cn": "Guest",
            "codePage": "0",
            "countryCode": "0",
            "dSCorePropagationData": [
                "2024-01-22T06:37:40Z",
                "1601-01-01T00:00:01Z"
            ],
            "description": "Built-in account for guest access to the computer/domain",
            "distinguishedName": "CN=Guest,CN=Users,DC=testserver,DC=local",
            "instanceType": "4",
            "isCriticalSystemObject": true,
            "lastLogoff": "0",
            "lastLogon": "2185-07-21T23:34:33.709551616Z",
            "logonCount": "0",
            "memberOf": "CN=Guests,CN=Builtin,DC=testserver,DC=local",
            "name": "Guest",
            "objectCategory": "CN=Person,CN=Schema,CN=Configuration,DC=testserver,DC=local",
            "objectClass": [
                "top",
                "person",
                "organizationalPerson",
                "user"
            ],
            "objectGUID": "hSt/40XJQU6cf+J2XoYMHw==",
            "objectSid": "AQUAAAAAAAUVAAAA0JU2Fq1k30YZ7UPx9QEAAA==",
            "primaryGroupID": "514",
            "pwdLastSet": "2185-07-21T23:34:33.709551616Z",
            "sAMAccountName": "Guest",
            "sAMAccountType": "805306368",
            "uSNChanged": "8197",
            "uSNCreated": "8197",
            "userAccountControl": "66082",
            "whenChanged": "2024-01-22T06:36:59Z",
            "whenCreated": "2024-01-22T06:36:59Z"
        },
        "whenChanged": "2024-01-22T06:36:59Z"
    },
    "user": {
        "id": "CN=Guest,CN=Users,DC=testserver,DC=local"
    },
    "labels": {
        "identity_source": "activedirectory-1"
    }
}
```

## Logs reference

### User

This is the `User` dataset.

{{fields "user"}}

### Device

This is the `Device` dataset.

{{fields "device"}}
