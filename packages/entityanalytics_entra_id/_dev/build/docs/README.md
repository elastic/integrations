# Microsoft Entra ID Entity Analytics

This integration retrieves users, with group memberships, from Microsoft Entra ID
(formerly Azure Active Directory).

## Configuration

The necessary API permissions need to be granted in Microsoft Entra in order for the
integration to function properly:

| Permission           | Type        |
|----------------------|-------------|
| GroupMember.Read.All | Application |
| User.Read.All        | Application |

For a full guide on how to set up the necessary App Registration, permission
granting, and secret configuration, follow this [guide](https://learn.microsoft.com/en-us/graph/auth-v2-service).

## Usage

The integration periodically contacts Microsoft Entra ID using the Graph API,
retrieving updates for users and groups, updates its internal cache of user
metadata and group membership information, and ships updated user metadata to
Elasticsearch.

Fetching and shipping updates occurs in one of two processes: **full synchronizations**
and **incremental updates**. Full synchronizations will send the entire list of
users in state, along with write markers to indicate the start and end of the
synchronization event. Incremental updates will only send data for changed users
during that event. Changes on a user can come in many forms, whether it be a
change to the user's metadata, a user was added or deleted, or group membership
was changed (either direct or transitive). By default, full synchronizations
occur every 24 hours and incremental updates occur every hour. These intervals
may be customized to suit your use case.

## Sample Events

{{event "entity"}}

The "write markers" bounding a full synchronization:

```json
{
  "input": {
    "type": "entity-analytics"
  },
  "@timestamp": "2023-03-22T14:34:37.693Z",
  "ecs": {
    "version": "8.7.0"
  },
  "data_stream": {
    "namespace": "ep",
    "type": "logs",
    "dataset": "entityanalytics_entra_id.entity"
  },
  "event": {
    "agent_id_status": "verified",
    "ingested": "2023-03-22T14:34:41Z",
    "start": "2023-03-22T14:34:37.693Z",
    "action": "started",
    "category": [
      "iam"
    ],
    "type": [
      "user",
      "info"
    ],
    "dataset": "entityanalytics_entra_id.entity"
  },
  "labels": {
    "identity_source": "entity-analytics-entityanalytics_entra_id.entity-d59eafe1-0583-4d42-b298-2bd30ef0b3b7"
  }
}
```

```json
{
  "input": {
    "type": "entity-analytics"
  },
  "@timestamp": "2023-03-22T14:34:40.684Z",
  "ecs": {
    "version": "8.7.0"
  },
  "data_stream": {
    "namespace": "ep",
    "type": "logs",
    "dataset": "entityanalytics_entra_id.entity"
  },
  "event": {
    "agent_id_status": "verified",
    "ingested": "2023-03-22T14:34:41Z",
    "action": "completed",
    "end": "2023-03-22T14:34:40.684Z",
    "category": [
      "iam"
    ],
    "type": [
      "user",
      "info"
    ],
    "dataset": "entityanalytics_entra_id.entity"
  },
  "labels": {
    "identity_source": "entity-analytics-entityanalytics_entra_id.entity-d59eafe1-0583-4d42-b298-2bd30ef0b3b7"
  }
}
```

{{fields "entity"}}
