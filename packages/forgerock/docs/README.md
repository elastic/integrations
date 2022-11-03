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
| forgerock.action | The synchronization action, depicted as a Common REST action. | keyword |
| forgerock.after | Specifies the JSON representation of the object after the activity. | object |
| forgerock.after.sunAMAuthInvalidAttemptsData | Example JSON representation of the object after the activity. | keyword |
| forgerock.before | Specifies the JSON representation of the object prior to the activity. | object |
| forgerock.before.sunAMAuthInvalidAttemptsData | Example JSON representation of the object prior to the activity. | object |
| forgerock.changedFields | Specifies the fields that were changed. | keyword |
| forgerock.client.ip | The client IP. | keyword |
| forgerock.component | The service utilized. | keyword |
| forgerock.entries | The JSON representation of the details of an authentication module, chain, tree, or node. | object |
| forgerock.eventName | The name of the audit event. | keyword |
| forgerock.exception | Stack trace of the exception. | keyword |
| forgerock.http.request.headers | The headers of the HTTP request. | object |
| forgerock.http.request.headers.accept | The accept parameter for the request. | keyword |
| forgerock.http.request.headers.accept-api-version | The accept-api-version header of the HTTP request. | keyword |
| forgerock.http.request.headers.content-type | The content-type header of the HTTP request. | keyword |
| forgerock.http.request.headers.host | The host header of the HTTP request. | keyword |
| forgerock.http.request.headers.origin | The origin header of the HTTP request. | keyword |
| forgerock.http.request.headers.user-agent | The user-agent header of the HTTP request. | keyword |
| forgerock.http.request.headers.x-forwarded-for | The x-forwarded-for header of the HTTP request. | keyword |
| forgerock.http.request.headers.x-forwarded-proto | The x-forwaded-proto header of the HTTP request. | keyword |
| forgerock.http.request.headers.x-requested-with | The x-requested with header of the HTTP request. | keyword |
| forgerock.http.request.queryParameters | The query parameter string of the HTTP request. | object |
| forgerock.http.request.secure | A flag describing whether or not the HTTP request was secure. | boolean |
| forgerock.level | The log level. | keyword |
| forgerock.linkQualifier | ForgeRock's link qualifier applied to the action. | keyword |
| forgerock.mapping | Name of the mapping used for the synchronization operation. | keyword |
| forgerock.message | Human readable text about the action. | keyword |
| forgerock.method | The authentication method, such as `JWT` or `MANAGED_USER`. | keyword |
| forgerock.objectId | Specifies the identifier of an object that has been created, updated, or deleted. | keyword |
| forgerock.operation | The state change operation invoked. | keyword |
| forgerock.passwordChanged | Boolean specifying whether changes were made to the password. | boolean |
| forgerock.principal | The array of accounts used to authenticate. | keyword |
| forgerock.provider | The social identity provider name. | keyword |
| forgerock.realm | The realm where the operation occurred. | keyword |
| forgerock.request.detail | Details around the response status. | object |
| forgerock.request.detail.grant_type | The request's grant type. | keyword |
| forgerock.request.detail.scope | The request's scope. | keyword |
| forgerock.request.detail.token_type_hint | The request's token type. | keyword |
| forgerock.request.operation | The request operation. | keyword |
| forgerock.request.protocol | The protocol associated with the request; REST or PLL. | keyword |
| forgerock.response.detail | Details around the response status. | object |
| forgerock.response.detail.active | A flag for whether or not the response was active. | boolean |
| forgerock.response.detail.client_id | The responses's client id. | keyword |
| forgerock.response.detail.revision | The responses's revision. | keyword |
| forgerock.response.detail.scope | The responses's scope. | keyword |
| forgerock.response.detail.token_type | The responses's token type. | keyword |
| forgerock.response.detail.username | The responses's username. | keyword |
| forgerock.response.elapsedTime | Time to execute event. | date |
| forgerock.response.elapsedTimeUnits | Units for response time. | keyword |
| forgerock.response.status | Status indicator, usually SUCCESS/SUCCESSFUL or FAIL/FAILED. | keyword |
| forgerock.result | Status indicator, usually SUCCESS/SUCCESSFUL or FAIL/FAILED. | keyword |
| forgerock.revision | Specifies the object revision number. | integer |
| forgerock.roles | IDM roles associated with the request. | keyword |
| forgerock.runAs | The user to run the activity as. | keyword |
| forgerock.situation | The synchronization situation as documented https://backstage.forgerock.com/docs/idm/7.2/synchronization-guide/chap-situations-actions.html#sync-situations | keyword |
| forgerock.source | The source of the event. | keyword |
| forgerock.sourceObjectId | Object ID on the source system. | keyword |
| forgerock.targetObjectId | Object ID on the target system | keyword |
| forgerock.topic | The topic of the event. | keyword |
| forgerock.trackingIds | Specifies a unique random string generated as an alias for each AM session ID and OAuth 2.0 token. | keyword |
| http.request.Path | The path of the HTTP request. | keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.response.body.content | The full HTTP response body. | wildcard |
| http.response.body.content.text | Multi-field of `http.response.body.content`. | match_only_text |
| http.response.status_code | HTTP response status code. | long |
| observer.vendor | Vendor name of the observer. | keyword |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| service.name | Name of the service data is collected from. The name of the service is normally user given. This allows for distributed services that run on multiple hosts to correlate the related instances based on the name. In the case of Elasticsearch the `service.name` could contain the cluster name. For Beats the `service.name` is by default a copy of the `service.type` field if no name is specified. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| transaction.id | Unique identifier of the transaction within the scope of its trace. A transaction is the highest level of work measured within a service, such as a request to a server. | keyword |
| user.effective.id | Unique identifier of the user. | keyword |
| user.id | Unique identifier of the user. | keyword |
