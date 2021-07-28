# Audit

## Logs

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| elasticsearch.audit.action | The name of the action that was executed | keyword |
| elasticsearch.audit.component |  | keyword |
| elasticsearch.audit.event_type | The type of event that occurred: anonymous_access_denied, authentication_failed, access_denied, access_granted, connection_granted, connection_denied, tampered_request, run_as_granted, run_as_denied | keyword |
| elasticsearch.audit.indices | Indices accessed by action | keyword |
| elasticsearch.audit.invalidate.apikeys.owned_by_authenticated_user |  | boolean |
| elasticsearch.audit.layer | The layer from which this event originated: rest, transport or ip_filter | keyword |
| elasticsearch.audit.message |  | text |
| elasticsearch.audit.origin.type | Where the request originated: rest (request originated from a REST API request), transport (request was received on the transport channel), local_node (the local node issued the request) | keyword |
| elasticsearch.audit.realm | The authentication realm the authentication was validated against | keyword |
| elasticsearch.audit.request.id | Unique ID of request | keyword |
| elasticsearch.audit.request.name | The type of request that was executed | keyword |
| elasticsearch.audit.url.params | REST URI parameters | keyword |
| elasticsearch.audit.user.realm | The user's authentication realm, if authenticated | keyword |
| elasticsearch.audit.user.roles | Roles to which the principal belongs | keyword |
| elasticsearch.audit.user.run_as.name |  | keyword |
| elasticsearch.audit.user.run_as.realm |  | keyword |
| elasticsearch.cluster.name | Name of the cluster | keyword |
| elasticsearch.cluster.uuid | UUID of the cluster | keyword |
| elasticsearch.component | Elasticsearch component from where the log event originated | keyword |
| elasticsearch.index.id | Index id | keyword |
| elasticsearch.index.name | Index name | keyword |
| elasticsearch.node.id | ID of the node | keyword |
| elasticsearch.node.name | Name of the node | keyword |
| elasticsearch.shard.id | Id of the shard | keyword |
| http.request.body.content | The full HTTP request body. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | keyword |
| user.name | Short name or login of the user. | keyword |

