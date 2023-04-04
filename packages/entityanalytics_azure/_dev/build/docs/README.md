# Azure Active Directory Entity Analytics

This integration retrieves users, with group memberships, from Azure Active Directory (AD).

## Configuration

The necessary API permissions need to be granted in Azure in order for the
integration to function properly:

| Permission           | Type        |
|----------------------|-------------|
| GroupMember.Read.All | Application |
| User.Read.All        | Application |

For a full guide on how to set up the necessary App Registration, permission
granting, and secret configuration, follow this [guide](https://learn.microsoft.com/en-us/graph/auth-v2-service).

## Usage

The integration periodically contacts Azure Active Directory using the Graph API,
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

A user document:

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
    "dataset": "entityanalytics_azure.users"
  },
  "event": {
    "agent_id_status": "verified",
    "ingested": "2023-03-22T14:34:41Z",
    "action": "user-discovered",
    "category": [
      "iam"
    ],
    "type": [
      "user",
      "info"
    ],
    "dataset": "entityanalytics_azure.users"
  },
  "user": {
    "full_name": "Sample Person",
    "phone": [
      "123-555-3671"
    ],
    "work": {
      "location": "682 St N, Somewhere, ABC, XYZ"
    },
    "name": [
      "Sample.Person@example.com"
    ],
    "last_name": "Person",
    "id": "feb6a386-612a-4ed1-9b13-2adc73074a19",
    "first_name": "Sample",
    "job_title": "Engineer",
    "email": "Sample_Person@example.com",
    "enabled": false
  },
  "labels": {
    "identity_source": "entity-analytics-entityanalytics_azure.users-d59eafe1-0583-4d42-b298-2bd30ef0b3b7"
  }
}
```

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
    "dataset": "entityanalytics_azure.users"
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
    "dataset": "entityanalytics_azure.users"
  },
  "labels": {
    "identity_source": "entity-analytics-entityanalytics_azure.users-d59eafe1-0583-4d42-b298-2bd30ef0b3b7"
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
    "dataset": "entityanalytics_azure.users"
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
    "dataset": "entityanalytics_azure.users"
  },
  "labels": {
    "identity_source": "entity-analytics-entityanalytics_azure.users-d59eafe1-0583-4d42-b298-2bd30ef0b3b7"
  }
}
```

## Exported fields

{{fields "users"}}
