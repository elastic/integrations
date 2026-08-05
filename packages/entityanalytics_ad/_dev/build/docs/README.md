# Active Directory Entity Analytics

This Active Directory Entity Analytics integration allows users to securely stream User Entities data to Elastic Security via the Active Directory LDAP look-ups. When integrated with Elastic Security, this valuable data can be leveraged within Elastic for risk-scoring scenarios (e.g., context enrichments) and detecting advanced analytics (UBA) use cases.

## Upgrading to v0.15.0 from v0.14 and lower of the integration

In v0.15.0 of the integration the user and device data was split into separate data streams. The data ingested into your index will be the same but you may need to update device searches if you were using them.

**NOTE**: When you upgrade from a version prior to v0.15.0 you will need to reconfigure the integration and enable it due to internal changes in the package. See [Resolve conflicts](https://www.elastic.co/guide/en/fleet/current/upgrade-integration.html#resolve-conflicts) in the Fleet documentation for details.

## Data streams

The Active Directory Entity Analytics integration collects identity data.

- **User** is used to retrieve all user entries available from an Active Directory server.
- **Device** is used to retrieve all device entries available from an Active Directory server.
- **Group** contains standalone documents for Active Directory groups that have no direct members, collected when the *Include empty groups* option is enabled. Groups with members are already represented through membership enrichment on user and device entities.

## Requirements

Elastic Agent must be installed for standard deployments. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### Agentless deployment

This integration supports agentless deployment, where the collection agent runs in Elastic's cloud rather than inside your network. Because the agent must still speak LDAP to an Active Directory server, the server must be reachable over the public internet on TCP port 636 (LDAPS). Plain LDAP on port 389 is not accepted in this configuration.

Agentless deployment works with:

- **Microsoft Entra Domain Services (Azure AD DS)** — when the "Allow secure LDAP access over the internet" option is enabled on the managed domain, the domain is assigned a public IP address on port 636. Microsoft recommends restricting inbound access to known source IP ranges using an NSG rule. See [Configure secure LDAP for Microsoft Entra Domain Services](https://learn.microsoft.com/en-us/entra/identity/domain-services/tutorial-configure-ldaps) for setup instructions. Check Elastic's documentation for the current agentless egress IP ranges to use in your NSG rule.
- **JumpCloud Cloud LDAP** — `ldap.jumpcloud.com:636` is a public endpoint and requires no additional configuration.
- **Okta LDAP Interface** — `<org>.ldap.okta.com:636` is a public endpoint and requires no additional configuration.

Agentless deployment does **not** work without additional network connectivity for:

- Traditional on-premises Active Directory domain controllers (not internet-exposed)
- AWS Managed Microsoft AD (VPC-internal only)
- Google Cloud Managed Microsoft AD (private network only)

For on-premises AD that is not internet-accessible, use standard agent-based deployment with an Elastic Agent running inside your network.

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

The Active Directory provider periodically contacts the server, retrieves updates for users and devices, updates its internal cache of metadata, and ships updated records to Elasticsearch.

Fetching and shipping updates occurs in one of two processes: **full synchronizations** and **incremental updates**. Full synchronizations send the entire list of users and devices in state. Incremental updates send only records that changed since the last sync. Changes include metadata updates, additions, and deletions. By default, full synchronizations occur every 24 hours and incremental updates occur every 15 minutes. These intervals may be customized to suit your use case.

By default this integration uses **minimal-state sync**, which routes user and device documents directly to the `user` and `device` data streams without writing synchronization marker events to the `entity` data stream. Existing policies that were created before this default was introduced are updated to use minimal-state sync on upgrade.

If you require synchronization marker events — start and end markers written to the `entity` data stream around each full synchronization — you can enable the legacy sync mode by setting the **Use minimal state** option to `false` in the integration configuration. Note that this option is not available when the integration is deployed in agentless mode.

This integration provides an **asset inventory**, a point-in-time snapshot of which users and devices exist and their current properties. It does not provide an audit trail of who changed what, or when. If you need to track administrative changes to Active Directory objects, consider collecting Windows Security event logs (e.g., Event IDs 4720, 4722, 4738, 4743) via the [System integration](https://docs.elastic.co/integrations/system).

## Sample Events

A user document:

```json
{
    "@timestamp": "2024-02-05T06:37:40.876026-05:00",
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

### Group

This is the `Group` dataset. It contains standalone documents for Active Directory groups that have no direct members, collected when the *Include empty groups* option is enabled. Groups with members are already represented through membership enrichment on user and device entities.

{{fields "group"}}
