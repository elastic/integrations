# ForgeRock Identity Platform

TBD

### Configuration

TBD

### Example event

TBD 

**Exported fields**

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.domain | The domain name of the client system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.id | Unique ID to describe the event. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
| forgerock.component | The service utilized. | keyword |
| forgerock.entries | The JSON representation of the details of an authentication module, chain, tree, or node. | object |
| forgerock.eventName | The name of the audit event. | keyword |
| forgerock.http.request.headers | The headers of the HTTP request. | object |
| forgerock.http.request.queryParameters | The query parameter string of the HTTP request. | object |
| forgerock.method | The authentication method, such as `JWT` or `MANAGED_USER`. | keyword |
| forgerock.operation | The state change operation invoked. | keyword |
| forgerock.principal | The array of accounts used to authenticate. | keyword |
| forgerock.provider | The social identity provider name. | keyword |
| forgerock.realm | The realm where the operation occurred. | keyword |
| forgerock.request.detail | Extra details about an 'action' request. | object |
| forgerock.request.operation | The request operation. | keyword |
| forgerock.request.protocol | The protocol associated with the request; REST or PLL. | keyword |
| forgerock.roles | IDM roles associated with the request. | keyword |
| forgerock.runAs | The user to run the activity as. | keyword |
| forgerock.source | The source of the event. | keyword |
| forgerock.topic | The topic of the event. | keyword |
| forgerock.trackingIds | Specifies a unique random string generated as an alias for each AM session ID and OAuth 2.0 token. | keyword |
| http.request.Path | The path of the HTTP request. | keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.response.body.content | The full HTTP response body. | wildcard |
| http.response.body.content.text | Multi-field of `http.response.body.content`. | match_only_text |
| http.response.status_code | HTTP response status code. | long |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| transaction.id | Unique identifier of the transaction within the scope of its trace. A transaction is the highest level of work measured within a service, such as a request to a server. | keyword |
| user.effective.id | Unique identifier of the user. | keyword |
| user.id | Unique identifier of the user. | keyword |
